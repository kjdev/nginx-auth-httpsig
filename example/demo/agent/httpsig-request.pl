#!/usr/bin/env perl
# Signs an HTTP request the way a web-bot-auth crawler would (Dictionary-
# form Signature-Agent, @target-uri/@authority/signature-agent components)
# and execs curl with the resulting headers. Reuses tests/prove/lib/HttpSig.pm
# so the demo signs requests exactly the way the integration tests do.
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/lib";
use Getopt::Long qw(GetOptions);
use HttpSig qw(default_request sign tamper_signature);

my %opt = (
    agent    => 'https://agent.bot.example',
    label    => 'sig1',
    target   => 'http://proxy:8080/',
    unsigned => 0,
    tamper   => 0,
);

GetOptions(
    'agent=s'  => \$opt{agent},
    'key=s'    => \$opt{key},
    'keyid=s'  => \$opt{keyid},
    'label=s'  => \$opt{label},
    'target=s' => \$opt{target},
    'unsigned' => \$opt{unsigned},
    'tamper'   => \$opt{tamper},
) or die "usage: $0 --agent URL --key PATH --keyid ID [--target URL] [--label NAME] [--unsigned] [--tamper]\n";

my ($scheme, $authority, $path) = $opt{target} =~ m{^(https?)://([^/]+)(/.*)?$}
    or die "httpsig-request.pl: cannot parse --target \"$opt{target}\"\n";
$path = '/' unless defined $path;

my @headers;

unless ($opt{unsigned}) {
    die "httpsig-request.pl: --key is required unless --unsigned\n"
        unless defined $opt{key};
    die "httpsig-request.pl: --keyid is required unless --unsigned\n"
        unless defined $opt{keyid};

    my $sig_agent = qq{$opt{label}="$opt{agent}"};

    my $req = default_request(
        scheme    => $scheme,
        authority => $authority,
        target    => $path,
        headers   => [['Signature-Agent', $sig_agent]],
    );

    my ($input, $sig) = sign(
        label      => $opt{label},
        keyfile    => $opt{key},
        components => ['@target-uri', '@authority', 'signature-agent'],
        params     => [
            ['created', time(),         'integer'],
            ['expires', time() + 300,   'integer'],
            ['keyid',   $opt{keyid},    'string'],
            ['alg',     'ed25519',      'string'],
            ['tag',     'web-bot-auth', 'string'],
        ],
        req => $req,
    );

    $sig = tamper_signature($sig) if $opt{tamper};

    push @headers, '-H', "Signature-Agent: $sig_agent";
    push @headers, '-H', "Signature-Input: $input";
    push @headers, '-H', "Signature: $sig";
}

exec('curl', '-sS', '-i', @headers, $opt{target})
    or die "httpsig-request.pl: exec curl failed: $!\n";
