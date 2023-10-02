import configparser

def validate_ini(file_path):
    """
    Validates the configuration file

    :param file_path: Path to the configuration file
    :return: Tuple of boolean and message
    """
    # Define the expected sections and fields
    expected_fields = {
        'System': [
            'domain', 
            'create_grpc_self_cert', 
            'log_level',
            'log_file_size_mb',
            'log_file_count', 
            'log_to_console', 
            'max_grpc_workers', 
            'grpc_port'
        ],
        'Database': [
            'db_host', 
            'db_port', 
            'db_username_encrypted', 
            'db_password_encrypted', 
            'db_name', 
            'db_pool_size', 
            'db_ca_path'
        ],
        'Wallet': [
            'algorithm', 
            'classic_address', 
            'secret_encrypted', 
            'offload_classic_address', 
            'offload_over_threshold'
        ],
        'Terms': [
            'payment_type', 
            'inquiry_expiration', 
            'payment_polling_interval', 
            'min_channel_funding', 
            'channel_expiration', 
            'destination_tag'
        ],
        'Ledger': ['ledger_url'],
        'SchedulesAndSettings': [
            'past_due_kicker', 
            'claim_window_seconds', 
            'expired_window_seconds', 
            'offload_interval_seconds'
        ],
        'gGRP_Certificate': [
            'generate_self_signed_cert', 
            'server_cert_name', 
            'server_key_name', 
            'common_name', 
            'country_name', 
            'organization_name', 
            'email_address', 
            'san_dns_1', 
            'san_dns_2', 
            'validity_days'
        ]
    }

    # Parse the .ini file
    config = configparser.ConfigParser()
    config.read(file_path)

    # Check each section and field
    for section, fields in expected_fields.items():
        if section not in config:
            return False, f"Section '{section}' is missing"
        for field in fields:
            if field not in config[section]:
                return False, f"Field '{field}' in section '{section}' is missing"
            if not config[section][field]:
                return False, f"Field '{field}' in section '{section}' has no value"

    return True, "Validation passed"


