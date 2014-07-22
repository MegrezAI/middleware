#+
# Copyright 2014 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################
import logging
import re

from django.db import models
from django.utils.translation import ugettext_lazy as _

from freenasUI import choices
from freenasUI.freeadmin.models import Model, PathField

log = logging.getLogger("directoryservice.models")

DS_TYPE_NONE = 0
DS_TYPE_ACTIVEDIRECTORY = 1
DS_TYPE_LDAP = 2
DS_TYPE_NIS = 3
DS_TYPE_NT4 = 4

def directoryservice_to_enum(ds_type):
    enum = DS_TYPE_NONE
    ds_dict = {
        'ActiveDirectory': DS_TYPE_ACTIVEDIRECTORY,
        'LDAP': DS_TYPE_LDAP,
        'NIS': DS_TYPE_NIS,
        'NT4': DS_TYPE_NT4
    }

    try:
        enum = ds_dict[ds_type]
    except: 
        pass

    return enum

def enum_to_directoryservice(enum):
    ds = None
    ds_dict = {
        DS_TYPE_ACTIVEDIRECTORY: 'ActiveDirectory',
        DS_TYPE_LDAP: 'LDAP',
        DS_TYPE_NIS: 'NIS',
        DS_TYPE_NT4: 'NT4'
    }

    try: 
        ds = ds_dict[enum]
    except: 
        pass

    return ds

IDMAP_TYPE_NONE = 0
IDMAP_TYPE_AD = 1
IDMAP_TYPE_AUTORID = 2
IDMAP_TYPE_HASH = 3
IDMAP_TYPE_LDAP = 4
IDMAP_TYPE_NSS = 5
IDMAP_TYPE_RFC2307 = 6
IDMAP_TYPE_RID = 7
IDMAP_TYPE_TDB = 8
IDMAP_TYPE_TDB2 = 9

def idmap_to_enum(idmap_type):
    enum = IDMAP_TYPE_NONE 
    idmap_dict = {
        'idmap_ad': IDMAP_TYPE_AD,
        'idmap_autorid': IDMAP_TYPE_AUTORID,
        'idmap_hash': IDMAP_TYPE_HASH,
        'idmap_ldap': IDMAP_TYPE_LDAP,
        'idmap_nss': IDMAP_TYPE_NSS,
        'idmap_rfc2307': IDMAP_TYPE_RFC2307,
        'idmap_rid': IDMAP_TYPE_RID,
        'idmap_tdb': IDMAP_TYPE_TDB,
        'idmap_tdb2': IDMAP_TYPE_TDB2
    }

    try:
        enum = idmap_dict[idmap_type]
    except:
        pass 

    return enum

def enum_to_idmap(enum):
    idmap = None
    idmap_dict = {
        IDMAP_TYPE_AD: 'idmap_ad',
        IDMAP_TYPE_AUTORID: 'idmap_autorid',
        IDMAP_TYPE_HASH: 'idmap_hash',
        IDMAP_TYPE_LDAP: 'idmap_ldap',
        IDMAP_TYPE_NSS: 'idmap_nss',
        IDMAP_TYPE_RFC2307: 'idmap_rfc2307',
        IDMAP_TYPE_RID: 'idmap_rid',
        IDMAP_TYPE_TDB: 'idmap_tdb',
        IDMAP_TYPE_TDB2: 'idmap_tdb2'
    }

    try:
        idmap = idmap_dict[enum]
    except:
        pass

    return idmap


class idmap_ad(Model):
    idmap_ad_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    )
    idmap_ad_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )
    idmap_ad_schema_mode = models.CharField(
        verbose_name=_("Schema Mode"),
        max_length=120,
        help_text=_(
            'Defines the schema that idmap_ad should use when querying '
            'Active Directory regarding user and group information. '
            'This can be either the RFC2307 schema support included '
            'in Windows 2003 R2 or the Service for Unix (SFU) schema. '
            'For SFU 3.0 or 3.5 please choose "sfu", for SFU 2.0 please '
            'choose "sfu20". Please note that primary group membership '
            'is currently always calculated via the "primaryGroupID" '
            'LDAP attribute.'
        ),
        choices=(
            ('rfc2307', _('rfc2307')),
            ('sfu', _('sfu')),
            ('sfu20', _('sfu20')),
        ),
        default='rfc2307'
    )

    class Meta:
        verbose_name = _("AD Idmap")
        verbose_name_plural = _("AD Idmap")

    class FreeAdmin:
        deletable = False


class idmap_autorid(Model):
    idmap_autorid_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    ) 
    idmap_autorid_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )
    idmap_autorid_rangesize = models.IntegerField(
        verbose_name=_("Range Size"),
        help_text=_(
           "Defines the number of uids/gids available per domain range. "
           "The minimum needed value is 2000. SIDs with RIDs larger "
           "than this value will be mapped into extension ranges "
           "depending upon number of available ranges. If the autorid "
           "backend runs out of available ranges, mapping requests for "
           "new domains (or new extension ranges for domains already "
           "known) are ignored and the corresponding map is discarded."
        ),
        default=100000
    )
    idmap_autorid_readonly = models.BooleanField(
        verbose_name=_("Read Only"),
        help_text=_(
            "Turn the module into read-only mode. No new ranges will "
            "be allocated nor will new mappings be created in the "
            "idmap pool."
        ),
        default=False
    )
    idmap_autorid_ignore_builtin = models.BooleanField(
        verbose_name=_("Ignore Builtin"),
        help_text=_("Ignore any mapping requests for the BUILTIN domain."),
        default=False
    )

    class Meta:
        verbose_name = _("AutoRID Idmap")
        verbose_name_plural = _("AutoRID Idmap")

    class FreeAdmin:
        deletable = False


class idmap_hash(Model):
    idmap_hash_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=90000001
    )
    idmap_hash_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=100000000
    )
    idmap_hash_range_name_map = PathField(
        verbose_name=_("Name Map"),
        help_text=_(
           'Specifies the absolute path to the name mapping file '
           'used by the nss_info API. Entries in the file are of '
           'the form "unix name = qualified domain name". Mapping '
           'of both user and group names is supported.'
        )
    )

    class Meta:
        verbose_name = _("Hash Idmap")
        verbose_name_plural = _("Hash Idmap")

    class FreeAdmin:
        deletable = False


class idmap_ldap(Model):
    idmap_ldap_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    )
    idmap_ldap_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )
    idmap_ldap_ldap_base_dn = models.CharField(
        verbose_name=_("Base DN"),
        max_length=120,
        help_text=_(
            'Defines the directory base suffix to use for SID/uid/gid '
            'mapping entries. If not defined, idmap_ldap will default '
            'to using the "ldap idmap suffix" option from smb.conf.'
        ),
        blank=True
    )
    idmap_ldap_ldap_user_dn = models.CharField( 
        verbose_name=_("User DN"),
        max_length=120,
        help_text=_(
            "Defines the user DN to be used for authentication. The "
            "secret for authenticating this user should be stored with "
            "net idmap secret (see net(8)). If absent, the ldap "
            "credentials from the ldap passdb configuration are used, "
            "and if these are also absent, an anonymous bind will be "
            "performed as last fallback."
        ),
        blank=True
    )
    idmap_ldap_ldap_url = models.CharField(
        verbose_name=_("URL"),
        max_length=255,
        help_text=_("Specifies the LDAP server to use for "
            "SID/uid/gid map entries.")
    )

    class Meta:
        verbose_name = _("LDAP Idmap")
        verbose_name_plural = _("LDAP Idmap")

    class FreeAdmin:
        deletable = False


class idmap_nss(Model):
    idmap_nss_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    )
    idmap_nss_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )

    class Meta:
        verbose_name = _("NSS Idmap")
        verbose_name_plural = _("NSS Idmap")

    class FreeAdmin:
        deletable = False


class idmap_rfc2307(Model):
    idmap_rfc2307_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    )
    idmap_rfc2307_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )
    idmap_rfc2307_ldap_server = models.CharField(
        verbose_name=_("LDAP Server"),
        max_length=120,
        help_text=_(
            "Defines the type of LDAP server to use. This can either "
            "be the LDAP server provided by the Active Directory server "
            "(ad) or a stand-alone LDAP server."
        ),
        choices=(
            ('ad', _('ad')),
            ('stand-alone', _('stand-alone')),
        ),
        default='ad'
    )
    idmap_rfc2307_bind_path_user = models.CharField(
        verbose_name=_("User Bind Path"),
        max_length=120, 
        help_text=_("Specifies the bind path where user objects "
            "can be found in the LDAP server."
        )
    )
    idmap_rfc2307_bind_path_group = models.CharField(
        verbose_name=_("Group Bind Path"),
        max_length=120, 
        help_text=_("Specifies the bind path where group objects can "
            "be found in the LDAP server."
        )
    )
    idmap_rfc2307_user_cn = models.BooleanField(
        verbose_name=_("User CN"),
        help_text=_("Query cn attribute instead of uid attribute "
            "for the user name in LDAP."
        ),
        default=False
    )
    idmap_rfc2307_cn_realm = models.BooleanField(
        verbose_name=_("CN Realm"),
        help_text=_("Append @realm to cn for groups (and users if "
            "user_cn is set) in LDAP."
        ),
        default=False
    )
    idmap_rfc2307_ldap_domain = models.CharField(
        verbose_name=_("LDAP Domain"),
        max_length=120,
        help_text=_(
            "When using the LDAP server in the Active Directory server, "
            "this allows to specify the domain where to access the "
            "Active Directory server. This allows using trust "
            "relationships while keeping all RFC 2307 records in one "
            "place. This parameter is optional, the default is to "
            "access the AD server in the current domain to query LDAP"
            "records."
        ),
        blank=True
    )
    idmap_rfc2307_ldap_url = models.CharField(
        verbose_name=_("LDAP URL"),
        max_length=255,
        help_text=_("When using a stand-alone LDAP server, this "
            "parameter specifies the ldap URL for accessing the LDAP server."
        ),
        blank=True
    )
    idmap_rfc2307_ldap_user_dn = models.CharField(
        verbose_name=_("LDAP User DN"),
        max_length=120,
        help_text=_(
            "Defines the user DN to be used for authentication. The "
            "secret for authenticating this user should be stored with "
            "net idmap secret (see net(8)). If absent, an anonymous "
            "bind will be performed."
        ),
        blank=True
    )
    idmap_rfc2307_ldap_realm = models.CharField(
        verbose_name=_("LDAP Realm"),
        max_length=120,
        help_text=_(
            "Defines the realm to use in the user and group names. "
            "This is only required when using cn_realm together with "
            "a stand-alone ldap server."
        ),
        blank=True
    )

    class Meta:
        verbose_name = _("RFC2307 Idmap")
        verbose_name_plural = _("RFC2307 Idmap")

    class FreeAdmin:
        deletable = False


class idmap_rid(Model):
    idmap_rid_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=10000
    )
    idmap_rid_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=90000000
    )

    class Meta:
        verbose_name = _("RID Idmap")
        verbose_name_plural = _("RID Idmap")

    class FreeAdmin:
        deletable = False


class idmap_tdb(Model):
    idmap_tdb_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=90000001
    ) 
    idmap_tdb_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=100000000
    )

    class Meta:
        verbose_name = _("TDB Idmap")
        verbose_name_plural = _("TDB Idmap")

    class FreeAdmin:
        deletable = False


class idmap_tdb2(Model):
    idmap_tdb2_range_low = models.IntegerField(
        verbose_name=_("Range Low"),
        default=90000001
    )
    idmap_tdb2_range_high = models.IntegerField(
        verbose_name=_("Range High"),
        default=100000000
    )
    idmap_tdb2_script = PathField(
        verbose_name=_("Script"),
        help_text=_(
            "This option can be used to configure an external program for "
            "performing id mappings instead of using the tdb counter. The "
            "mappings are then stored int tdb2 idmap database."
        )
    )

    class Meta:
        verbose_name = _("TDB2 Idmap")
        verbose_name_plural = _("TDB2 Idmap")

    class FreeAdmin:
        deletable = False


class directoryservice_idmap(Model):
    dsi_idmap_ad = models.ForeignKey(
        idmap_ad,
        null=True
    )
    dsi_idmap_autorid = models.ForeignKey(
        idmap_autorid,
        null=True
    )
    dsi_idmap_hash = models.ForeignKey( 
        idmap_hash,
        null=True
    )
    dsi_idmap_ldap = models.ForeignKey(
        idmap_ldap,
        null=True
    )
    dsi_idmap_nss = models.ForeignKey(
        idmap_nss,
        null=True
    )
    dsi_idmap_rfc2307 = models.ForeignKey(
        idmap_rfc2307,
        null=True
    )
    dsi_idmap_rid = models.ForeignKey(
        idmap_rid,
        null=True
    )
    dsi_idmap_tdb = models.ForeignKey(
        idmap_tdb,
        null=True
    )
    dsi_idmap_tdb2 = models.ForeignKey(
        idmap_tdb2,
        null=True
    )


class NT4(Model):
    ds_type = DS_TYPE_NT4

    nt4_dcname = models.CharField(
        verbose_name=_("Domain Controller"),
        max_length=120,
        help_text=_("Hostname of the domain controller to use."),
    )
    nt4_netbiosname = models.CharField(
        verbose_name=_("NetBIOS Name"),
        max_length=120,
        help_text=_("System hostname"),
        blank=True
    )
    nt4_workgroup = models.CharField(
        verbose_name=_("Workgroup Name"),
        max_length=120,
        help_text=_("Workgroup or domain name in old format, eg WORKGROUP")
    )
    nt4_adminname = models.CharField(
        verbose_name=_("Administrator Name"),
        max_length=120,
        help_text=_("Domain administrator account name")
    )
    nt4_adminpw = models.CharField(
        verbose_name=_("Administrator Password"),
        max_length=120,
        help_text=_("Domain administrator account password.")
    )
    nt4_use_default_domain = models.BooleanField(
        verbose_name=_("Use Default Domain"),
        help_text=_("Set this if you want to use the default "
            "domain for users and groups."),
        default=False
    )
    nt4_idmap_backend = models.CharField(
        verbose_name=_("Idmap backend"),
        choices=choices.IDMAP_CHOICES,
        max_length=120,
        help_text=_("Idmap backend for winbind."),
        default=enum_to_idmap(IDMAP_TYPE_RID)
    )
    nt4_idmap_backend_type = models.ForeignKey(
        directoryservice_idmap,
        null=True
    )
    nt4_enable = models.BooleanField(
        verbose_name=_("Enable"),
        default=False,
    )

    def __init__(self, *args, **kwargs):
        super(NT4, self).__init__(*args, **kwargs)
        self.svc = 'nt4'

        if not self.nt4_netbiosname:
            from freenasUI.network.models import GlobalConfiguration
            gc_hostname = GlobalConfiguration.objects.all().order_by('-id')[0].gc_hostname
            if gc_hostname:
                m = re.match(r"^([a-zA-Z][a-zA-Z0-9]+)", gc_hostname)
                if m:
                    self.nt4_netbiosname = m.group(0).upper().strip()

    class Meta:
        verbose_name = _("NT4 Domain")
        verbose_name_plural = _("NT4 Domain")

    class FreeAdmin:
        deletable = False


class ActiveDirectory(Model):
    ds_type = DS_TYPE_ACTIVEDIRECTORY

    ad_domainname = models.CharField(
        verbose_name=_("Domain Name (DNS/Realm-Name)"),
        max_length=120,
        help_text=_("Domain Name, eg example.com")
    )
    ad_bindname = models.CharField(
        verbose_name=_("Domain Account Name"),
        max_length=120,
        help_text=_("Domain account name to bind as")
    )
    ad_bindpw = models.CharField(
        verbose_name=_("Domain Account Password"),
        max_length=120,
        help_text=_("Domain Account password.")
    )
    ad_netbiosname = models.CharField(
        verbose_name=_("NetBIOS Name"),
        max_length=120,
        help_text=_("System hostname"),
        blank=True
    )
    ad_use_keytab = models.BooleanField(
        verbose_name=_("Use keytab"),
        default=False,
    )
    ad_keytab = models.TextField(
        verbose_name=_("Kerberos keytab"),
        help_text=_("Kerberos keytab file"),
        blank=True,
        null=True,
    )
    ad_ssl = models.CharField(
        verbose_name=_("Encryption Mode"),
        max_length=120,
        help_text=_(
            "This parameter specifies whether to use SSL/TLS, e.g."
            " on/off/start_tls"
        ),
        choices=choices.LDAP_SSL_CHOICES,
        default='off'
    )
    ad_certfile = models.TextField(
        verbose_name=_("SSL Certificate"),
        blank=True,
        help_text=_("Upload your certificate file here.")
    )
    ad_verbose_logging = models.BooleanField(
        verbose_name=_("Verbose logging"),
        default=False
    )
    ad_unix_extensions = models.BooleanField(
        verbose_name=_("UNIX extensions"),
        help_text=_("Set this if your Active Directory has UNIX extensions."),
        default=False
    )
    ad_allow_trusted_doms = models.BooleanField(
        verbose_name=_("Allow Trusted Domains"),
        help_text=_("Set this if you want to allow Trusted Domains."),
        default=False
    )
    ad_use_default_domain = models.BooleanField(
        verbose_name=_("Use Default Domain"),
        help_text=_("Set this if you want to use the default "
            "domain for users and groups."),
        default=False
    )
    ad_dcname = models.CharField(
        verbose_name=_("Domain Controller"),
        max_length=120,
        help_text=_("Hostname of the domain controller to use."),
        blank=True
    )
    ad_gcname = models.CharField(
        verbose_name=_("Global Catalog Server"),
        max_length=120,
        help_text=_("Hostname of the global catalog server to use."),
        blank=True
    )
    ad_krbname = models.CharField(
        verbose_name=_("Kerberos Server"),
        max_length=120,
        help_text=_("Hostname of the kerberos server to use."),
        blank=True
    )
    ad_kpwdname = models.CharField(
        verbose_name=_("Kerberos Password Server"),
        max_length=120,
        help_text=_("Hostname of the kerberos password server to use."),
        blank=True
    )
    ad_timeout = models.IntegerField(
        verbose_name=_("AD timeout"),
        help_text=_("Timeout for AD related commands."),
        default=10
    )
    ad_dns_timeout = models.IntegerField(
        verbose_name=_("DNS timeout"),
        help_text=_("Timeout for AD DNS queries."),
        default=10
    )
    ad_idmap_backend = models.CharField(
        verbose_name=_("Idmap backend"),
        choices=choices.IDMAP_CHOICES,
        max_length=120,
        help_text=_("Idmap backend for winbind."),
        default=enum_to_idmap(IDMAP_TYPE_AD)
    )
    ad_idmap_backend_type = models.ForeignKey(
        directoryservice_idmap,
        null=True
    )
    ad_enable = models.BooleanField(
        verbose_name=_("Enable"),
        default=False
    )

    def __init__(self, *args, **kwargs):
        super(ActiveDirectory, self).__init__(*args, **kwargs)
        self.svc = 'activedirectory'

        if not self.ad_netbiosname:  
            from freenasUI.network.models import GlobalConfiguration
            gc_hostname = GlobalConfiguration.objects.all().order_by('-id')[0].gc_hostname
            if gc_hostname:
                m = re.match(r"^([a-zA-Z][a-zA-Z0-9\.\-]+)", gc_hostname)
                if m:
                    self.ad_netbiosname = m.group(0).upper().strip()


    class Meta:
        verbose_name = _("Active Directory")
        verbose_name_plural = _("Active Directory")

    class FreeAdmin:
        deletable = False
        icon_model = "ActiveDirectoryIcon"


class NIS(Model):
    ds_type = DS_TYPE_NIS

    nis_domain = models.CharField(
        verbose_name=_("NIS domain"),
        max_length=120,
        help_text=_("NIS domain name")
    )
    nis_servers = models.CharField(
        verbose_name=_("NIS servers"),
        max_length=8192,
        help_text=_("Comma delimited list of NIS servers"),
        blank=True
    )
    nis_secure_mode = models.BooleanField(
        verbose_name=_("Secure mode"),
        help_text=_("Cause ypbind to run in secure mode"),
        default=False
    )
    nis_manycast = models.BooleanField(
        verbose_name=_("Manycast"),
        help_text=_("Cause ypbind to use 'many-cast' instead of broadcast"),
        default=False
    )
    nis_enable = models.BooleanField(
        verbose_name=_("Enable"),
        default=False,
    )

    def __init__(self, *args, **kwargs):
        super(NIS, self).__init__(*args, **kwargs)
        self.svc = 'nis'

    class Meta:
        verbose_name = _("NIS Domain")
        verbose_name_plural = _("NIS Domain")

    class FreeAdmin:
        deletable = False
        icon_model = "NISIcon"


class LDAP(Model):
    ds_type = DS_TYPE_LDAP

    ldap_hostname = models.CharField(
        verbose_name=_("Hostname"),
        max_length=120,
        help_text=_("The name or IP address of the LDAP server"),
        blank=True
    )
    ldap_basedn = models.CharField(
        verbose_name=_("Base DN"),
        max_length=120,
        help_text=_("The default base Distinguished Name (DN) to use for "
            "searches, eg dc=test,dc=org"),
        blank=True
    )
    ldap_binddn = models.CharField(
        verbose_name=_("Bind DN"),
        max_length=120,
        help_text=_("The distinguished name with which to bind to the "
            "directory server, e.g. cn=admin,dc=test,dc=org"),
        blank=True
    )
    ldap_bindpw = models.CharField(
        verbose_name=_("Bind password"),
        max_length=120,
        help_text=_("The credentials with which to bind."),
        blank=True
    )
    ldap_anonbind = models.BooleanField(
        verbose_name=_("Allow Anonymous Binding"),
        default=False
    )
    ldap_usersuffix = models.CharField(
        verbose_name=_("User Suffix"),
        max_length=120,
        help_text=_("This parameter specifies the suffix that is used for "
            "users when these are added to the LDAP directory, e.g. "
            "ou=Users"),
        blank=True
    )
    ldap_groupsuffix = models.CharField(
        verbose_name=_("Group Suffix"),
        max_length=120,
        help_text=_("This parameter specifies the suffix that is used "
            "for groups when these are added to the LDAP directory, e.g. "
            "ou=Groups"),
        blank=True
    )
    ldap_passwordsuffix = models.CharField(
        verbose_name=_("Password Suffix"),
        max_length=120,
        help_text=_("This parameter specifies the suffix that is used for "
            "passwords when these are added to the LDAP directory, e.g. "
            "ou=Passwords"),
        blank=True
    )
    ldap_machinesuffix = models.CharField(
        verbose_name=_("Machine Suffix"),
        max_length=120,
        help_text=_("This parameter specifies the suffix that is used for "
            "machines when these are added to the LDAP directory, e.g. "
            "ou=Computers"),
        blank=True
    )
    ldap_use_default_domain = models.BooleanField(
        verbose_name=_("Use default domain"),
        default=False,
        help_text=_("Set this if you want to use the default domain for users and groups.")
    )
    ldap_ssl = models.CharField(
        verbose_name=_("Encryption Mode"),
        max_length=120,
        help_text=_(
            "This parameter specifies whether to use SSL/TLS, e.g."
            " on/off/start_tls"
        ),
        choices=choices.LDAP_SSL_CHOICES,
        default='off'
    )
    ldap_certfile = models.TextField(
        verbose_name=_("SSL Certificate"),
        help_text=_("Upload your certificate file here."),
        blank=True
    )
    ldap_idmap_backend = models.CharField(
        verbose_name=_("Idmap backend"),
        choices=choices.IDMAP_CHOICES,
        max_length=120,
        help_text=_("Idmap backend for winbind."),
        default=enum_to_idmap(IDMAP_TYPE_LDAP)
    )
    ldap_idmap_backend_type = models.ForeignKey(
        directoryservice_idmap,
        null=True
    )
    ldap_enable = models.BooleanField(
        verbose_name=_("Enable"),
        default=False
    )

    def __init__(self, *args, **kwargs):
        super(LDAP, self).__init__(*args, **kwargs)
        self.svc = 'ldap'

    class Meta:
        verbose_name = _("LDAP")
        verbose_name_plural = _("LDAP")

    class FreeAdmin:
        deletable = False
        icon_model = "LDAPIcon"
