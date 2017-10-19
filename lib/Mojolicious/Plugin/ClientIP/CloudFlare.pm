package Mojolicious::Plugin::ClientIP::CloudFlare;

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

sub register {
    my ($self, $app, $conf) = @_;
    my $analyzed_headers = $conf->{analyzed_headers} // [qw/cf-pseudo-ipv4 cf-connecting-ip true-client-ip/];
    my $check_address = $conf->{v4_only} ? \&Data::Validate::IP::is_ipv4 : \&Data::Validate::IP::is_ip;
    $app->helper(client_ip => sub {
        my ($c) = @_;
        my $headers = $c->tx->req->headers;

        my @candidates = map { $headers->header($_) // () } @$analyzed_headers;
        push @candidates, do {
            # In this header, we expect:
            # client internal IP,maybe client external IP,any upstream proxies,cloudflare
            # We're interested in the IP address of whoever hit CloudFlare, so we drop the last one
            # then take the next one after that.
            my @ips = split /\s*,\s*/, $headers->header('x-forwarded-for');
            pop @ips if @ips > 1;
            $ips[-1];
        } if $headers->header('x-forwarded-for');

        # Fall back to what our upstream (nginx) detected
        push @candidates, $c->tx->remote_address;
        for my $ip (@candidates) {
            return $ip if $check_address->($ip);
        }
        return '';
    });

    return;
}

1;
