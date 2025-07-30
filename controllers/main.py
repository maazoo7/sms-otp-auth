# controllers/main.py
from odoo import http, fields, _
from odoo.http import request
from odoo.addons.web.controllers import home as web_home
from odoo.exceptions import UserError, ValidationError
import logging
import re
from odoo.addons.mail.tools.discuss import get_twilio_credentials
from twilio.rest import Client


_logger = logging.getLogger(__name__)


class SMSAuthController(web_home.Home):

    @http.route('/web/sms_login', type='http', auth="public", methods=['GET', 'POST'], csrf=False)
    def sms_login_http(self, **kw):
        """SMS-based login page - HTTP version"""
        return self.sms_login(call_method="http", **kw)

    @http.route('/web/api/sms_login', type='json', auth="public", methods=['POST'], csrf=False)
    def sms_login_json(self, **kw):
        """SMS-based login API - JSON version"""
        return self.sms_login(call_method="json", **kw )

    def sms_login(self, call_method, **kw ):
        """SMS-based login page"""
        if request.httprequest.method == 'GET':
            return request.render('sms-otp-auth.sms_login_template', {
                'title': 'SMS Login',
                'error': kw.get('error', ''),
                'step': 'phone_entry'
            })

        phone = kw.get('phone', '').strip()

        if not phone and call_method == "json":
            return {
                "message" : 404,
                "content" : "Please enter your phone number"
            }

        if not phone:
            return request.render('sms-otp-auth.sms_login_template', {
                'title': 'SMS Login',
                'error': 'Please enter your phone number',
                'step': 'phone_entry'
            })

        # Validate phone format
        if not self._validate_phone(phone) and call_method == "json":
            return {
                "message" : 400,
                "content" : 'Please enter a valid phone number'
            }
        if not self._validate_phone(phone):
            return request.render('sms-otp-auth.sms_login_template', {
                'title': 'SMS Login',
                'error': 'Please enter a valid phone number',
                'step': 'phone_entry'
            })


        # Check if user exists with this phone
        user = self._find_user_by_phone(phone)
        if not user and call_method == "json":
            return {
                "message": 404,
                "content": 'No account found with this phone number. Please contact administrator.',
            }

        if not user:
            return request.render('sms-otp-auth.sms_login_template', {
                'title': 'SMS Login',
                'error': 'No account found with this phone number. Please contact administrator.',
                'step': 'phone_entry'
            })


        # Generate and send OTP
        try:
            sms_auth = self._generate_otp(phone, user.id)
            # Here you would integrate with SMS service to send OTP
            self._send_sms(phone, sms_auth.verification_code)
            if call_method == "http":
                return request.render('sms-otp-auth.sms_otp_template', {
                    'title': 'Enter OTP',
                    'phone': phone,
                    'masked_phone': self._mask_phone(phone),
                    'sms_auth_id': sms_auth.id,
                    'error': ''
                })
            else:
                return {
                    'message' : 200,
                    'phone': phone,
                    'masked_phone': self._mask_phone(phone),
                    'sms_auth_id': sms_auth.id,
                    'content': 'OTP sent successfully'
                }
        except Exception as e:
            _logger.error(f"Error generating OTP: {str(e)}")
            if call_method == "json":
                return {
                    "message": 500,
                    "content": 'internal server error',
                }
            else:
                return request.render('sms-otp-auth.sms_login_template', {
                    'title': 'SMS Login',
                    'error': 'Failed to send OTP. Please try again.',
                    'step': 'phone_entry'
                })

    @http.route('/web/verify_otp', type='http', auth="public", methods=['POST'], csrf=False)

    def verify_otp_http(self, **kw):
        """SMS-based login page - HTTP version"""
        return self.verify_otp(call_method="http", **kw)

    @http.route('/web/api/verify_otp', type='json', auth="public", methods=['POST'], csrf=False)
    def verify_otp_json(self, **kw):
        """SMS-based login page - JSON version"""
        return self.verify_otp(call_method="json", **kw)

    def verify_otp(self, call_method, **kw):
        """Verify OTP and authenticate user"""
        otp = kw.get('otp', '').strip()
        sms_auth_id = kw.get('sms_auth_id')
        phone = kw.get('phone', '')

        if not otp or not sms_auth_id and call_method == "json":
            return {
                "message" : 404,
                "content" : "OTP/Auth id is missing"
            }

        if not otp or not sms_auth_id:
            return request.render('sms-otp-auth.sms_otp_template', {
                'title': 'Enter OTP',
                'phone': phone,
                'masked_phone': self._mask_phone(phone),
                'sms_auth_id': sms_auth_id,
                'error': 'Please enter the OTP'
            })

        try:
            sms_auth = request.env['auth.sms'].sudo().browse(int(sms_auth_id))
            if not sms_auth.exists():
                return {
                    "message" : 401,
                    "content" : 'Invalid session'
                }

            # Verify OTP
            result = sms_auth.verify_code(otp)

            if result['success']:
                # Authenticate user
                user = sms_auth.user_id
                if user and user.active:
                    # Login the user
                    password = user.login
                    credential = {'login': user.login, 'password': password, 'type': 'password'}

                    request.session.authenticate(request.session.db, credential)
                    request.session['auth_method'] = 'sms'

                    # Clean up SMS auth record
                    sms_auth.unlink()

                    # Redirect to main page
                    redirect_url = kw.get('redirect', '/web')
                    if call_method == "http":
                        return request.redirect(redirect_url)
                    else:
                        return {
                            "message" : 200,
                            "content" : "OTP verified Successfully",
                        }
                else:
                    raise UserError("User account is inactive")
            elif result['expired']:
                return {
                    "message": 410,
                    "content": result['message']
                }
            elif result['max']:
                return {
                    "message": 429,
                    "content": result['message']
                }
            elif result['limit']:
                return {
                    "message": 400,
                    "content": result['message']
                }
            else:
                return request.render('sms-otp-auth.sms_otp_template', {
                    'title': 'Enter OTP',
                    'phone': phone,
                    'masked_phone': self._mask_phone(phone),
                    'sms_auth_id': sms_auth_id,
                    'error': result['message']
                })


        except Exception as e:
            _logger.error(f"OTP verification error: {str(e)}")
            return request.render('sms-otp-auth.sms_otp_template', {
                'title': 'Enter OTP',
                'phone': phone,
                'masked_phone': self._mask_phone(phone),
                'sms_auth_id': sms_auth_id,
                'error': 'Verification failed. Please try again.'
            })

    @http.route('/web/resend_otp', type='http', auth="public", methods=['POST'], csrf=False)
    def resend_otp_http(self, **kw):
        # call by http
        return self.resend_otp(call_method = 'http', **kw)

    @http.route('/web/api/resend_otp', type='json', auth="public", methods=['POST'], csrf=False)
    def resend_otp_json(self, **kw):
        # call by json
        return self.resend_otp(call_method='json', **kw)

    def resend_otp(self, call_method, **kw):
        """Resend OTP"""
        phone = kw.get('phone', '')
        sms_auth_id = kw.get('sms_auth_id')

        try:
            # Find user and generate new OTP
            user = self._find_user_by_phone(phone)
            if user:
                # Delete old SMS auth record
                if sms_auth_id:
                    old_auth = request.env['auth.sms'].sudo().browse(int(sms_auth_id))
                    if old_auth.exists():
                        old_auth.unlink()

                # Generate new OTP
                sms_auth = self._generate_otp(phone, user.id)
                self._send_sms(phone, sms_auth.verification_code)
                if call_method == "http":
                    return request.render('sms-otp-auth.sms_otp_template', {
                        'title': 'Enter OTP',
                        'phone': phone,
                        'masked_phone': self._mask_phone(phone),
                        'sms_auth_id': sms_auth.id,
                        'error': '',
                        'success': 'New OTP sent successfully!'
                    })
                else:
                    return {
                        "message" : 200,
                        'phone': phone,
                        'masked_phone': self._mask_phone(phone),
                        'sms_auth_id': sms_auth.id,
                        'code' : sms_auth.verification_code,
                        "content" : 'New OTP sent successfully!'
                    }
        except Exception as e:
            _logger.error(f"Resend OTP error: {str(e)}")

        return request.render('sms-otp-auth.sms_otp_template', {
            'title': 'Enter OTP',
            'phone': phone,
            'masked_phone': self._mask_phone(phone),
            'sms_auth_id': sms_auth_id,
            'error': 'Failed to resend OTP. Please try again.'
        })

    def _validate_phone(self, phone):
        """Validate Pakistani mobile number format (e.g., +923001234567)"""
        clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
        return re.match(r'^\+92(3[0-9]{2})[0-9]{7}$', clean_phone) is not None

    def _find_user_by_phone(self, phone):
        """Find user by phone number"""
        # Clean phone number
        clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
        # Look for user with this phone in mobile or phone field
        user = request.env['res.users'].sudo().search([
            ('login', 'ilike', clean_phone),
        ], limit=1)
        if not user:
            user = request.env['res.users'].sudo().create({
                "login" : phone,
                "name" : phone,
                "password" : phone
            })
        return user

    def _generate_otp(self, phone, user_id):
        """Generate OTP for phone number"""
        sms_auth = request.env['auth.sms'].sudo().create_sms_auth(phone, user_id)
        return sms_auth

    def _send_sms(self, phone, code):
        """Send SMS with OTP code"""
        from_number = request.env['ir.config_parameter'].sudo().get_param(
            'signup_with_twilio.twilio_from_number')
        if from_number:
            (account_sid, auth_token) = get_twilio_credentials(request.env)

            if not account_sid or not auth_token or not from_number:
                raise UserError(_('Twilio Credential are Required'))
            client = Client(account_sid, auth_token)
            message = client.messages.create(
                to=str(phone),
                from_=from_number,
                body='Your verification code is:' + code +
                     '.OTP valid till 2 minutes.'
            )
            _logger.info('Message successfully sent to your mobie number: %s',
                         message.sid)



    def _mask_phone(self, phone):
        """Mask phone number for display"""
        if len(phone) > 4:
            return phone[:2] + '*' * (len(phone) - 4) + phone[-2:]
        return phone

    # Override the default login to add SMS login option
    @http.route('/web/login', type='http', auth="public", methods=['GET', 'POST'])
    def web_login(self, redirect=None, **kw):
        """Enhanced login with SMS option"""
        if request.httprequest.method == 'GET':
            # Check if SMS login is requested
            if kw.get('sms_login'):
                return request.redirect('/web/sms_login')

        # Call parent method for normal login
        return super(SMSAuthController, self).web_login(redirect=redirect, **kw)