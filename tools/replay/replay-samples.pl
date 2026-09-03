#!/usr/bin/env perl
# Replays Signature/Signature-Input/Signature-Agent/User-Agent headers
# captured from real crawler traffic, unmodified, against a running
# auth_httpsig proxy. created/expires are themselves signed parameters, so
# they cannot be rewritten for replay, and by replay time they are almost
# always outside auth_httpsig_max_skew; verification only succeeds if the
# proxy's max_skew has been widened for this purpose (see HTTPSIG_MAX_SKEW
# in the standalone proxy image). Samples signed over @target-uri also need
# the proxy to see the original scheme, so this script adds
# X-Forwarded-Proto when a sample was captured over https (see
# HTTPSIG_TRUST_X_FORWARDED_PROTO). Only "path" is used from each sample;
# "args" is a WAF fingerprint shared by every row, not a real query string.
#
# --list-agents extracts the Signature-Agent authorities present in the
# sample file (sending no requests) so they can be reviewed before
# registering any of them as auth_httpsig_trusted_agent /
# HTTPSIG_TRUSTED_AGENTS.
use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use JSON::PP qw(decode_json);

my %opt = (
    target      => 'http://localhost:8082',
    limit       => 0,
    list_agents => 0,
);

GetOptions(
    'target=s'    => \$opt{target},
    'limit=i'     => \$opt{limit},
    'list-agents' => \$opt{list_agents},
) or die usage();

my $file = shift @ARGV or die usage();

(my $base = $opt{target}) =~ s{/+$}{};

open my $fh, '<', $file or die "replay-samples.pl: cannot open $file: $!\n";

sub usage {
    return "usage: $0 <jsonl-file> [--target BASE-URL] [--limit N] [--list-agents]\n";
}

# Signature-Agent samples show up in three shapes: an SFV Dictionary
# ("g=\"https://agent.bot.goog\""), a bare SFV String
# ("\"https://bot.duckduckgo.com\""), or an unquoted URL
# ("https://bot.duckduckgo.com"). All that's needed here is the host, so
# pull the first quoted or bare https?:// URL out and skip real SFV parsing.
sub agent_hosts {
    my ($signature_agent) = @_;
    return () unless defined $signature_agent;

    my @urls = $signature_agent =~ /"(https?:\/\/[^"]+)"/g;
    @urls = $signature_agent =~ /^\s*(https?:\/\/\S+?)\s*$/
        unless @urls;

    return grep { defined } map { m{^https?://([^/?#]+)} } @urls;
}

# Values from the sample file reach the terminal via print/printf below;
# neutralize control characters (e.g. ANSI escapes) so a crafted sample
# cannot manipulate the display.
sub display_safe {
    my ($s) = @_;
    return $s unless defined $s;
    $s =~ s/[\x00-\x1f\x7f]/?/g;
    return $s;
}

if ($opt{list_agents}) {
    my %count;

    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\r\z//;
        next if $line eq '';

        my $sample = eval { decode_json($line) };
        unless (ref $sample eq 'HASH') {
            warn "replay-samples.pl: skipping unparsable line $.\n";
            next;
        }

        my %seen;
        for my $host (agent_hosts($sample->{signature_agent})) {
            $count{$host}++ unless $seen{$host}++;
        }
    }

    close $fh;

    for my $host (sort { $count{$b} <=> $count{$a} } keys %count) {
        printf "%6d  %s\n", $count{$host}, display_safe($host);
    }

    exit 0;
}

my ($sent, $skipped) = (0, 0);

SAMPLE: while (1) {
    last if $opt{limit} && $sent >= $opt{limit};

    my $line = <$fh>;
    last unless defined $line;
    chomp $line;
    $line =~ s/\r\z//;
    next if $line eq '';

    my $sample = eval { decode_json($line) };
    if (ref $sample ne 'HASH') {
        warn "replay-samples.pl: skipping unparsable line $.\n";
        $skipped++;
        next;
    }

    unless (defined $sample->{signature} && $sample->{signature} =~ /\S/
            && defined $sample->{signature_input}
            && $sample->{signature_input} =~ /\S/) {
        $skipped++;
        next;
    }

    my $path = $sample->{path} // '/';
    if ($path !~ m{\A/[^\s\x00-\x1f?#]*\z}) {
        warn "replay-samples.pl: skipping line $. with unsafe path: "
            . display_safe($path) . "\n";
        $skipped++;
        next;
    }

    my $method = $sample->{method} // 'GET';
    if ($method !~ /\A[!#\$%&'*+\-.^_`|~0-9A-Za-z]+\z/) {
        warn "replay-samples.pl: skipping line $. with unsafe method: "
            . display_safe($method) . "\n";
        $skipped++;
        next;
    }

    my $host = $sample->{host};

    # curl does not reject embedded CR/LF in -H or -X values (verified
    # against curl 8.18.0: both split the request into extra header
    # lines), so any field going into one is checked here rather than
    # relying on curl to refuse it.
    for my $field (qw(signature signature_input signature_agent user_agent host)) {
        next unless defined $sample->{$field};
        if ($sample->{$field} =~ /[\r\n\0]/) {
            warn "replay-samples.pl: skipping line $. with CR/LF in $field\n";
            $skipped++;
            next SAMPLE;
        }
    }

    my @headers;
    push @headers, '-H', "Signature-Input: $sample->{signature_input}";
    push @headers, '-H', "Signature: $sample->{signature}";
    push @headers, '-H', "Signature-Agent: $sample->{signature_agent}"
        if defined $sample->{signature_agent} && length $sample->{signature_agent};
    push @headers, '-H', "User-Agent: $sample->{user_agent}"
        if defined $sample->{user_agent} && length $sample->{user_agent};
    push @headers, '-H', "Host: $host"
        if defined $host && length $host;
    push @headers, '-H', 'X-Forwarded-Proto: https'
        if defined $sample->{scheme} && lc($sample->{scheme}) eq 'https';

    my @cmd = ('curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}',
               '-X', $method, @headers, '--globoff', "$base$path");

    print '-> ', display_safe($method), ' ', display_safe($path),
        ' (host=', display_safe($host // '-'), ') ';
    if (system(@cmd) != 0) {
        if ($? == -1) {
            warn "replay-samples.pl: failed to run curl for line $.: $!\n";
        }
        else {
            warn sprintf("replay-samples.pl: curl exited %d for line %d\n",
                          $? >> 8, $.);
        }
    }
    print "\n";

    $sent++;
}

close $fh;

print STDERR "replay-samples.pl: sent $sent, skipped $skipped\n";
