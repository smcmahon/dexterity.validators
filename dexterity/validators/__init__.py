import re

import z3c.form.validator
import zope.interface

# from Products.CMFPlone.utils import safe_unicode

from plone.app.dexterity import MessageFactory as _

# protocols for isURL validator, the secure (*s) variants are automagically
# added
protocols = ('http', 'ftp', 'irc', 'news', 'imap', 'gopher', 'jabber',
    'webdav', 'smb', 'fish', 'ldap', 'pop3', 'smtp', 'sftp', 'ssh', 'feed'
    )

EMAIL_RE = u"([0-9a-zA-Z_&.'+-]+!)*[0-9a-zA-Z_&.'+-]+@(([0-9a-zA-Z]([0-9a-zA-Z-]*[0-9a-z-A-Z])?\.)+[a-zA-Z]{2,6}|([0-9]{1,3}\.){3}[0-9]{1,3})$"


class RegExValidator(z3c.form.validator.SimpleFieldValidator):

    regex = re.compile(u".+")
    ignore = ''
    msgid = u"regex_invalid"
    errmsg = u"Invalid: ${value}"

    def validate(self, value):
        super(RegExValidator, self).validate(value)

        if self.ignore:
            tvalue = self.ignore.sub(u'', value)
        else:
            tvalue = value

        if not self.regex.match(tvalue):
            raise zope.interface.Invalid(_(self.msgid, self.errmsg, mapping={u'value': value}))


class isEmail(RegExValidator):

    regex = re.compile("^" + EMAIL_RE)
    ignore = ''
    msgid = u"email_invalid"
    errmsg = u"${value} is not a valid email address."

isEMail = isEmail


class isUSPhoneNumber(RegExValidator):

    regex = re.compile(r'^\d{10}$')
    ignore = re.compile('[\(\)\-\s]')
    msgid = u"usphone_invalid"
    errmsg = u"${value} is not a valid phone number with area code."


class isInternationalPhoneNumber(RegExValidator):

    regex = re.compile(r'^\d+$')
    ignore = re.compile('[\(\)\-\s\+]')
    msgid = u"intphone_invalid"
    errmsg = u"${value} is not a valid international phone number."


class isZipCode(RegExValidator):

    regex = re.compile(r'^(\d{5}|\d{9})$')
    ignore = ''
    msgid = u"zipcode_invalid"
    errmsg = u"${value} is not a valid zip code."


class isURL(RegExValidator):

    regex = re.compile(r'(%s)s?://[^\s\r\n]+' % '|'.join(protocols))
    ignore = ''
    msgid = u"url_invalid"
    errmsg = u"${value} is not a valid URL."


class isWebAddress(RegExValidator):

    regex = re.compile(r'https?://[^\s\r\n]+')
    ignore = ''
    msgid = u"url_invalid"
    errmsg = u"${value} is not a valid web address. Make sure you include http(s)://"
