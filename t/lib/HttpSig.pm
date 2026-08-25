package HttpSig;

use strict;
use warnings;

use Exporter 'import';
use MIME::Base64 qw(encode_base64 decode_base64);
use File::Temp qw(tempfile);

our @EXPORT_OK = qw(
    default_request
    sign
    tamper_signature
);

# RFC 8941 SF-string: quote, backslash-escape '\' and '"'.
sub sf_string {
    my ($s) = @_;
    (my $escaped = $s) =~ s/([\\"])/\\$1/g;
    return qq{"$escaped"};
}

sub serialize_params {
    my ($params) = @_;
    my $out = '';

    for my $p (@$params) {
        my ($key, $value, $type) = @$p;
        $out .= ";$key";
        $out .= '=' . ($type eq 'integer' ? $value : sf_string($value))
            if defined $value;
    }

    return $out;
}

sub serialize_inner_list {
    my ($components, $params) = @_;
    my $list = '(' . join(' ', map { sf_string($_) } @$components) . ')';
    return $list . serialize_params($params);
}

# Mirrors ngx_http_auth_httpsig_build_request(): default port stripped only
# for the exact "http"/"https" schemes, path/query split on the first '?'
# of the raw target (never percent-decoded or normalized).
sub default_request {
    my (%a) = @_;
    my $scheme    = $a{scheme}    // 'http';
    my $authority = $a{authority} // 'localhost';
    my $target    = $a{target}    // '/';

    if (($scheme eq 'http' && $authority =~ s/:80$//)
        || ($scheme eq 'https' && $authority =~ s/:443$//))
    {
        # default port already stripped above
    }

    my ($path, $query, $has_query);
    if ((my $qpos = index($target, '?')) >= 0) {
        $path      = substr($target, 0, $qpos);
        $query     = substr($target, $qpos + 1);
        $has_query = 1;
    } else {
        $path      = $target;
        $query     = '';
        $has_query = 0;
    }

    return {
        method    => $a{method} // 'GET',
        scheme    => $scheme,
        authority => $authority,
        path      => $path,
        query     => $query,
        has_query => $has_query,
        headers   => $a{headers} // [],
    };
}

sub derive_component {
    my ($name, $req) = @_;

    return $req->{method}                                if $name eq '@method';
    return $req->{scheme}                                if $name eq '@scheme';
    return $req->{authority}                              if $name eq '@authority';
    return length($req->{path}) ? $req->{path} : '/'      if $name eq '@path';
    return $req->{has_query} ? "?$req->{query}" : '?'     if $name eq '@query';

    if ($name eq '@request-target') {
        return $req->{path} . ($req->{has_query} ? "?$req->{query}" : '');
    }

    if ($name eq '@target-uri') {
        return "$req->{scheme}://$req->{authority}$req->{path}"
            . ($req->{has_query} ? "?$req->{query}" : '');
    }

    die "HttpSig: unsupported derived component \"$name\"";
}

sub field_value {
    my ($name, $headers) = @_;
    my @values = map { $_->[1] } grep { lc($_->[0]) eq lc($name) } @$headers;
    die "HttpSig: missing field \"$name\" for signature base" unless @values;
    return join(', ', @values);
}

# RFC 9421 SS2.5: one "<serialized identifier>: <value>" line per covered
# component, each terminated by LF except the final @signature-params line.
sub build_base_string {
    my ($components, $params, $req) = @_;
    my @lines;

    for my $name (@$components) {
        my $value = $name =~ /^\@/
            ? derive_component($name, $req)
            : field_value($name, $req->{headers});
        push @lines, sf_string($name) . ': ' . $value;
    }

    push @lines,
        sf_string('@signature-params') . ': '
        . serialize_inner_list($components, $params);

    return join("\n", @lines);
}

sub ed25519_sign_raw {
    my ($keyfile, $message) = @_;

    my ($in_fh, $in_path)   = tempfile(UNLINK => 1);
    my (undef,  $out_path)  = tempfile(UNLINK => 1);

    print $in_fh $message;
    close $in_fh;

    my $rc = system('openssl', 'pkeyutl', '-sign', '-rawin',
                     '-inkey', $keyfile, '-in', $in_path, '-out', $out_path);
    die "HttpSig: openssl pkeyutl -sign failed (rc=$rc)" if $rc != 0;

    open my $out_fh, '<:raw', $out_path or die "HttpSig: $!";
    local $/;
    my $raw = <$out_fh>;
    close $out_fh;

    return $raw;
}

# Builds Signature-Input / Signature header values for $req, signed with
# the Ed25519 key at $keyfile. %params entries become Signature-Input
# parameters in the given order; e.g. [['created', 1700000000, 'integer'],
# ['tag', 'web-bot-auth', 'string']].
#
# Returns (signature_input_value, signature_value, base_string).
sub sign {
    my (%a) = @_;
    my $label      = $a{label}      // 'sig1';
    my $keyfile    = $a{keyfile}    // die "HttpSig: keyfile required";
    my $components = $a{components} // die "HttpSig: components required";
    my $params     = $a{params}     // die "HttpSig: params required";
    my $req        = $a{req}        // die "HttpSig: req required";

    my $base = build_base_string($components, $params, $req);
    my $raw_sig = ed25519_sign_raw($keyfile, $base);
    my $sig_b64 = encode_base64($raw_sig, '');

    my $input_value = "$label=" . serialize_inner_list($components, $params);
    my $sig_value   = "$label=:$sig_b64:";

    return ($input_value, $sig_value, $base);
}

# Flips a bit in the decoded signature bytes of a "label=:base64:" Signature
# header value, re-encoding the result. Used to build tampered-signature
# fixtures for negative tests.
sub tamper_signature {
    my ($sig_value) = @_;

    $sig_value =~ /:([A-Za-z0-9+\/=]+):/
        or die "HttpSig: not a Signature header value: $sig_value";
    my $raw = decode_base64($1);
    substr($raw, 0, 1) = chr(ord(substr($raw, 0, 1)) ^ 0xff);
    my $tampered_b64 = encode_base64($raw, '');

    (my $out = $sig_value) =~ s/:[A-Za-z0-9+\/=]+:/:$tampered_b64:/;
    return $out;
}

1;
