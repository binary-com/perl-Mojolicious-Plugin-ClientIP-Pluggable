use strict;
use warnings;

use Test::More;
use Test::Mojo;

{
    use Mojolicious::Lite;

    plugin 'ClientIP::CloudFlare', v4_only => 1;

    get '/' => sub {
        my $c = shift;
        $c->render(text => $c->client_ip);
    };

    app->start;
}

my $t = Test::Mojo->new;

subtest "cf-pseudo-ipv4" => sub {
    my $tx = $t->ua->build_tx(GET => '/' => {'cf-pseudo-ipv4' => '1.2.3.4'});
    $t->request_ok($tx)->content_is('1.2.3.4');
};

subtest "x-forwarded-for" => sub {
    my $tx = $t->ua->build_tx(GET => '/' => {'x-forwarded-for' => '1.1.1.1,2.2.2.2'});
    $t->request_ok($tx)->content_is('1.1.1.1');
};

subtest "no headers" => sub {
    my $tx = $t->ua->build_tx(GET => '/');
    $t->request_ok($tx)->content_is('127.0.0.1');
};

subtest "non-ip in header" => sub {
    my $tx = $t->ua->build_tx(GET => '/' => {'cf-pseudo-ipv4' => 'a1.2.3.4'});
    $t->request_ok($tx)->content_is('127.0.0.1');
};

subtest "ipv6 ignored" => sub {
    my $tx = $t->ua->build_tx(GET => '/' => {'cf-connecting-ip' => '2400:cb00:f00d:dead:beef:1111:2222:3333', 'x-forwarded-for' => '1.1.1.1'});
    $t->request_ok($tx)->content_is('1.1.1.1');
};


done_testing;
