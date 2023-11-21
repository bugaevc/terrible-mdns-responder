project('terrible-mdns-responder', 'c',
    version: '0.1.0',
    license: 'AGPL3+',
)

systemd = dependency('systemd', required: get_option('systemd'))

subdir('src')

config = configuration_data()
prefix = get_option('prefix')
sbindir = get_option('sbindir')
daemon_path = prefix / sbindir / 'terrible-mdns-responder'

if systemd.found()
    config.set('DAEMON_PATH', daemon_path)
    configure_file(
        input: 'terrible-mdns-responder.service.in',
        output: 'terrible-mdns-responder.service',
        configuration: config,
        install_dir: systemd.get_variable('systemdsystemunitdir'),
    )
else
    config.set_quoted('DAEMON_PATH', daemon_path)
    configure_file(
        input: 'terrible-mdns-responder.in',
        output: 'terrible-mdns-responder',
        configuration: config,
        install_dir: '/etc/init.d',
    )
endif
