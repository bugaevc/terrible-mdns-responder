project('terrible-mdns-responder', 'c',
    version: '0.1.0',
    license: 'AGPL3+',
)

subdir('src')

config = configuration_data()
prefix = get_option('prefix')
daemon_path = prefix / 'sbin/terrible-mdns-responder'
config.set_quoted('DAEMON_PATH', daemon_path)
configure_file(
    input: 'terrible-mdns-responder.in',
    output: 'terrible-mdns-responder',
    configuration: config,
    install_dir: '/etc/init.d',
)
