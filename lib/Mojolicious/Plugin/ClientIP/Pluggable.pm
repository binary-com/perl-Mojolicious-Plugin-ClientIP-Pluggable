package Mojolicious::Plugin::ClientIP::Pluggable;

=head1 NAME

Mojolicious::Plugin::ClientIP::CloudFlare - CloudFlare-aware client IP detection plugin

=head1 SYNOPSIS

    use Mojolicious::Lite;

    plugin 'ClientIP::CloudFlare', v4_only => 1;
    # for headers analisys customization
    # plugin 'ClientIP::CloudFlare', analyzed_headers => [qw/cf-pseudo-ipv4 cf-connecting-ip/];


    get '/' => sub {
        my $c = shift;
        $c->render(text => $c->client_ip);
    };

    app->start;

=head1 DESCRIPTION

Mojolicious::Plugin::ClientIP::CloudFlare is a Mojolicious plugin to get an IP address, possibly
available beyound different CloudFlare-headers as well as X-Forwarded-For header.

The pluging is inspired by L<Mojolicious::Plugin::ClientIP>.

=head1 METHODS

=head2 client_ip

Find a client IP address from different CloudFlare headers, with fallback to C<X-Forwarded-For> header,
and then to L<Mojo::Transaction#remote_address>. If the valid IP address is not found (if you are looking
strictly for IPv4 address, but only IPv6-address is available via headers), it returns empty string.

=head1 OPTIONS

=head2 v4_only

Only IPv4 addresses are considered valid among the possible addresses.

    plugin 'ClientIP::CloudFlare', v4_only => 1;


=head2 analyzed_headers

Define order and names of CloudFlare-injected headers with client IP address.
By default it uses C<cf-pseudo-ipv4 cf-connecting-ip true-client-ip>.

    plugin 'ClientIP::CloudFlare', analyzed_headers => [qw/cf-pseudo-ipv4 cf-connecting-ip true-client-ip/].


More details at L<https://support.cloudflare.com/hc/en-us/articles/202494830-Pseudo-IPv4-Supporting-IPv6-addresses-in-legacy-IPv4-applications>,
L<https://support.cloudflare.com/hc/en-us/articles/200170986-How-does-CloudFlare-handle-HTTP-Request-headers>,
L<https://support.cloudflare.com/hc/en-us/articles/206776727-What-is-True-Client-IP>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 binary.com

=cut


use strict;
use warnings;

use Data::Validate::IP;

use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.01';

# for tests only
use constant SKIP_LOOPBACK => $ENV{CLIENTIP_PLUGGABLE_SKIP_LOOPBACK} || 1;

sub _check_ipv4 {
    my ($ip) = @_;
    return !Data::Validate::IP::is_unroutable_ipv4($ip)
        && !Data::Validate::IP::is_private_ipv4($ip)
        && (SKIP_LOOPBACK || !Data::Validate::IP::is_loopback_ipv4($ip));
}

sub _check_ipv6 {
    my ($ip) = @_;
    return !Data::Validate::IP::is_private_ipv6($ip)
        && !Data::Validate::IP::is_documentation_ipv6($ip)
        && (SKIP_LOOPBACK || !Data::Validate::IP::is_loopback_ipv6($ip));
}

sub _classify_ip {
    my ($ip) = @_;
    return Data::Validate::IP::is_ipv4($ip)
        ? 'ipv4'
        : Data::Validate::IP::is_ipv6($ip)
        ? 'ipv6'
        : undef;
}

sub _candatetes_iterator {
    my ($c, $analyzed_headers, $fallback_options) = @_;
    my $headers = $c->tx->req->headers;
    my @candidates = map { $headers->header($_) // () } @$analyzed_headers;
    my $comma_re = qr/\s*,\s*/;
    for my $fallback (map { lc } @$fallback_options) {
        if ($fallback eq 'x-forwarded-for') {
            my $xff = $headers->header('x-forwarded-for');
            next unless $xff;
            my @ips = split $comma_re, $xff;
            push @candidates, @ips;
        } elsif ($fallback eq 'remote_address') {
            push @candidates, $c->tx->remote_address
        } elsif ($fallback eq 'rfc-7239') {
            my $f = $headers->header('forwarded');
            next unless $f;
            my @pairs = map { split $comma_re, $_ } split ';', $f;
            my @ips = map {
                my $ipv4_mask = qr/\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/;
                # it is not completely valid ipv6 mask, but enough
                # to extract address. It will be validated later
                my $ipv6_mask = qr/[\w:]+/;
                if (/for=($ipv4_mask)|(?:"?\[($ipv6_mask)\].*"?)/i) {
                    ( $1 // $2 );
                } else {
                    ();
                }
            } @pairs;
            push @candidates, @ips;
        } else {
            warn "Unknown fallback option $fallback, ignoring";
        }
    }
    my $idx = 0;
    return sub {
        if($idx < @candidates) {
            return $candidates[$idx++];
        }
        return (undef);
    };
}

sub register {
    my ($self, $app, $conf) = @_;
    my $analyzed_headers = $conf->{analyze_headers} // die "Please, specify 'analyzed_headers' option";
    my %validator_for = (
        ipv4 => \&_check_ipv4,
        ipv6 => \&_check_ipv6,
    );
    my $restrict_family = $conf->{restrict_family};
    my $fallback_options = $conf->{fallbacks} // [qw/remote_address/];

    $app->helper(client_ip => sub {
        my ($c) = @_;

        my $next_candidate = _candatetes_iterator($c, $analyzed_headers, $fallback_options);
        while(my $ip = $next_candidate->()) {
            # generic check
            next unless Data::Validate::IP::is_ip($ip);

            # classify & check
            my $address_family = _classify_ip($ip);
            next unless $address_family;

            # possibly limit to acceptable address family
            next if $restrict_family && $restrict_family ne $address_family;

            # validate by family
            my $validator = $validator_for{$address_family};
            next unless $validator->($ip);

            # address seems valid, return it's textual representation
            return $ip;
        }
        return '';
    });

    return;
}

1;
