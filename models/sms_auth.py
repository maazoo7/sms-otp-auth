# models/sms_auth.py
from odoo import fields, models, api, _
from odoo.exceptions import UserError, ValidationError
from datetime import datetime, timedelta
import random
import string
import logging



_logger = logging.getLogger(__name__)


class SmsAuth(models.Model):
    _name = 'auth.sms'
    _description = 'SMS auth for users'
    _order = 'create_date desc'

    name = fields.Char(string='Reference', default='SMS Auth', required=True)
    phone_number = fields.Char(string='Phone Number', required=True, index=True)
    verification_code = fields.Char(string='Verification Code', required=True)
    user_id = fields.Many2one('res.users', string='User', required=True, index=True)
    is_verified = fields.Boolean(string='Is Verified', default=False)
    expiry_time = fields.Datetime(string='Code Expiry', required=True)
    attempts = fields.Integer(string='Verification Attempts', default=0)
    max_attempts = fields.Integer(string='Max Attempts', default=3)
    ip_address = fields.Char(string='IP Address')
    user_agent = fields.Text(string='User Agent')

    # Computed fields
    is_expired = fields.Boolean(string='Is Expired', compute='_compute_is_expired')
    remaining_attempts = fields.Integer(string='Remaining Attempts', compute='_compute_remaining_attempts')

    @api.depends('expiry_time')
    def _compute_is_expired(self):
        for record in self:
            record.is_expired = record.expiry_time < fields.Datetime.now()

    @api.depends('attempts', 'max_attempts')
    def _compute_remaining_attempts(self):
        for record in self:
            record.remaining_attempts = max(0, record.max_attempts - record.attempts)

    @api.model
    def generate_verification_code(self, length=4):
        """Generate a verification code"""
        return ''.join(random.choices(string.digits, k=length))

    @api.model
    def create_sms_auth(self, phone_number, user_id, expiry_minutes=2):
        """Create SMS authentication record with verification code"""
        # Clean up old records for this user/phone
        self._cleanup_old_records(phone_number, user_id)

        existing_record = self.search([
            ('expiry_time', '>', fields.Datetime.now()),
            ('attempts', '!=' , 3),
            ('user_id', '=' , user_id),
            ('is_verified', '=', False)
        ], limit=1)

        if not existing_record:
            # Generate code and expiry
            code = self.generate_verification_code()
            expiry = fields.Datetime.now() + timedelta(minutes=expiry_minutes)

            # Get request info if available
            request = self.env.context.get('request')
            ip_address = None
            user_agent = None

            if request:
                ip_address = request.httprequest.environ.get('REMOTE_ADDR')
                user_agent = request.httprequest.environ.get('HTTP_USER_AGENT')

            # Create record
            sms_auth = self.create({
                'name': f'SMS Auth - {phone_number}',
                'phone_number': phone_number,
                'verification_code': code,
                'user_id': user_id,
                'expiry_time': expiry,
                'attempts': 0,
                'ip_address': ip_address,
                'user_agent': user_agent,
            })


            _logger.info(f"SMS auth created for user {user_id}, phone {phone_number}")
            return sms_auth
        else:
            return existing_record

    def verify_code(self, entered_code):
        """Verify the entered code"""
        self.ensure_one()

        # Check if expired
        if self.is_expired:
            _logger.warning(f"Expired OTP verification attempt for {self.phone_number}")
            return {'success': False, 'expired': self.is_expired, 'limit' : False,  'max': False, 'message': _('Verification code has expired')}

        # Check max attempts
        if self.attempts >= self.max_attempts:
            _logger.warning(f"Max attempts exceeded for {self.phone_number}")
            return {'success': False, 'expired': False, 'max': self.attempts >= self.max_attempts, 'limit': False, 'message': _('Maximum verification attempts exceeded')}

        # Increment attempts
        self.attempts += 1

        # Verify code
        if self.verification_code == str(entered_code).strip():
            self.is_verified = True
            _logger.info(f"Successful OTP verification for {self.phone_number}")
            return {'success': True, 'message': _('Verification successful')}
        else:
            remaining = self.max_attempts - self.attempts
            if remaining > 0:
                message = _('Invalid verification code. %d attempts remaining.') % remaining
            else:
                message = _('Invalid verification code. Maximum attempts exceeded.')

            _logger.warning(f"Failed OTP verification for {self.phone_number}, attempts: {self.attempts}")
            return {'success': False, 'message': message, 'limit' : True, 'max' : False, 'expired' : False}

    @api.model
    def _cleanup_old_records(self, phone_number=None, user_id=None):
        """Clean up old/expired SMS auth records"""
        domain = [
            '|',
            ('expiry_time', '<', fields.Datetime.now()),
            ('is_verified', '=', True)
        ]

        if phone_number:
            domain.append(('phone_number', '=', phone_number))
        if user_id:
            domain.append(('user_id', '=', user_id))

        old_records = self.search(domain)
        if old_records:
            old_records.unlink()
            _logger.info(f"Cleaned up {len(old_records)} old SMS auth records")

    @api.model
    def cleanup_expired_records(self):
        """Cron job to clean up expired records"""
        expired_records = self.search([
            ('expiry_time', '<', fields.Datetime.now())
        ])

        if expired_records:
            count = len(expired_records)
            expired_records.unlink()
            _logger.info(f"Cleaned up {count} expired SMS auth records")

        return True

    def resend_code(self):
        """Resend verification code (generate new one)"""
        self.ensure_one()

        if self.is_verified:
            raise UserError(_('This verification has already been completed'))

        # Generate new code and extend expiry
        self.verification_code = self.generate_verification_code()
        self.expiry_time = fields.Datetime.now() + timedelta(minutes=2)
        self.attempts = 0

        _logger.info(f"OTP resent for {self.phone_number}")
        return True

    @api.constrains('phone_number')
    def _check_phone_number(self):
        for record in self:
            if not record.phone_number:
                raise ValidationError(_('Phone number is required'))

    @api.constrains('verification_code')
    def _check_verification_code(self):
        for record in self:
            if not record.verification_code or len(record.verification_code) < 4:
                raise ValidationError(_('Verification code must be at least 4 digits'))

    def name_get(self):
        result = []
        for record in self:
            name = f"{record.phone_number} - {record.create_date.strftime('%Y-%m-%d %H:%M')}"
            if record.is_verified:
                name += " (Verified)"
            elif record.is_expired:
                name += " (Expired)"
            result.append((record.id, name))
        return result


# Extend res.users to add phone validation
class ResUsers(models.Model):
    _inherit = 'res.users'

    @api.constrains('mobile', 'phone')
    def _check_phone_unique(self):
        """Ensure phone numbers are unique for active users"""
        for user in self:
            if user.mobile:
                duplicate = self.search([
                    ('mobile', '=', user.mobile),
                    ('active', '=', True),
                    ('id', '!=', user.id)
                ], limit=1)
                if duplicate:
                    raise ValidationError(_('Mobile number %s is already registered with another user') % user.mobile)

            if user.phone:
                duplicate = self.search([
                    ('phone', '=', user.phone),
                    ('active', '=', True),
                    ('id', '!=', user.id)
                ], limit=1)
                if duplicate:
                    raise ValidationError(_('Phone number %s is already registered with another user') % user.phone)