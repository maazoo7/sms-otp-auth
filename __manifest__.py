# -*- coding: utf-8 -*-
# Copyright 2025 GalaxyITC
{
    'name': 'SMS OTP Auth',
    'version': '1.0.0',
    'author': "BusinessFlow Systems",
    'website': "https://www.odoo.com",
    'category': 'Extra Tools/Authentication',
    'summary': "Module for SMS-based OTP Authentication",
    'description': """
        SMS OTP Auth module enables authentication using One-Time Passwords (OTP) via SMS. It includes:
            - Mobile number login/signup
            - OTP verification mechanism
            - Security and validation
            - Integration support with other modules
    """,
    'depends': [
        'base', 'portal', 'auth_signup', 'mail'
    ],
    'license': 'LGPL-3',
    'price': 50.00,
    'currency': 'USD',

    'data': [
        'security/ir.model.access.csv',
        'views/sms_auth.xml',
        'views/auth.xml',
        'views/res_config_setting_views.xml',
    ],
    'images': ['static/description/logo.png'],
    'auto_install': False,
    'application': True,
    'installable': True,
}
