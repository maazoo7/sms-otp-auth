# -*- coding: utf-8 -*-

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    """ Inherit the base settings to add a twilio from number """
    _inherit = 'res.config.settings'

    twilio_from_number = fields.Char(
        string='Twilio From Number', help="From number which used to send sms "
        "from the number",
        config_parameter='signup_with_twilio.twilio_from_number')
