requires 'Data::Validate::IP';
requires 'Mojolicious';
requires 'perl', '5.014';

on configure => sub {
    requires 'ExtUtils::MakeMaker', '6.64';
};

on build => sub {
    requires 'Test::Mojo';
    requires 'Test::More';
};
