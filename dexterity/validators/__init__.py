import re

import z3c.form.validator
import zope.interface

from plone.app.dexterity import _

# protocols for isURL validator, the secure (*s) variants are automagically
# added
protocols = ('http', 'ftp', 'irc', 'news', 'imap', 'gopher', 'jabber',
    'webdav', 'smb', 'fish', 'ldap', 'pop3', 'smtp', 'sftp', 'ssh', 'feed'
    )

EMAIL_RE = u"([0-9a-zA-Z_&.'+-]+!)*[0-9a-zA-Z_&.'+-]+@(([0-9a-zA-Z]([0-9a-zA-Z-]*[0-9a-z-A-Z])?\.)+[a-zA-Z]{2,6}|([0-9]{1,3}\.){3}[0-9]{1,3})$"


# regular expression validator that gets regex, ignore, msgid, errmsg
# from a class
def reValidate(value, recls):
    if not value:
        return True
    if recls.ignore:
        tvalue = recls.ignore.sub(u'', value)
    else:
        tvalue = value
    if not recls.regex.match(tvalue):
        raise zope.interface.Invalid(_(recls.msgid, recls.errmsg, mapping={u'value': value}))
    return True


class RegExValidator(z3c.form.validator.SimpleFieldValidator):

    regex = re.compile(u".+")
    ignore = u''
    msgid = u"regex_invalid"
    errmsg = u"Invalid: ${value}"

    def validate(self, value):
        super(RegExValidator, self).validate(value)
        reValidate(value, self.__class__)


class IsEmail(RegExValidator):

    regex = re.compile("^" + EMAIL_RE)
    ignore = ''
    msgid = u"email_invalid"
    errmsg = u"${value} is not a valid email address."


def isEmail(value):
    return reValidate(value, IsEmail)


class IsUSPhoneNumber(RegExValidator):

    regex = re.compile(r'^\d{10}$')
    ignore = re.compile('[\(\)\-\s]')
    msgid = u"usphone_invalid"
    errmsg = u"${value} is not a valid phone number with area code."


def isUSPhoneNumber(value):
    return reValidate(value, IsUSPhoneNumber)


class IsInternationalPhoneNumber(RegExValidator):

    regex = re.compile(r'^\d+$')
    ignore = re.compile('[\(\)\-\s\+]')
    msgid = u"intphone_invalid"
    errmsg = u"${value} is not a valid international phone number."


def isInternationalPhoneNumber(value):
    return reValidate(value, IsInternationalPhoneNumber)


class IsZipCode(RegExValidator):

    regex = re.compile(r'^(\d{5}|\d{9})$')
    ignore = ''
    msgid = u"zipcode_invalid"
    errmsg = u"${value} is not a valid zip code."


def isZipCode(value):
    return reValidate(value, IsZipCode)


class IsURL(RegExValidator):

    regex = re.compile(r'(%s)s?://[^\s\r\n]+' % '|'.join(protocols))
    ignore = ''
    msgid = u"url_invalid"
    errmsg = u"${value} is not a valid URL."


def isURL(value):
    return reValidate(value, IsURL)


class IsWebAddress(RegExValidator):

    regex = re.compile(r'https?://[^\s\r\n]+')
    ignore = ''
    msgid = u"webaddress_invalid"
    errmsg = u"${value} is not a valid web address. Make sure you include http:// or https://"


def isWebAddress(value):
    return reValidate(value, IsWebAddress)
