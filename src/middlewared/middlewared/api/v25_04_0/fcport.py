from typing import Dict, Literal

from pydantic import Field

from middlewared.api.base import BaseModel, Excluded, FibreChannelPortAlias, ForUpdateMetaclass, WWPN, excluded_field


class FCPortEntry(BaseModel):
    id: int
    port: FibreChannelPortAlias
    wwpn: WWPN | None
    wwpn_b: WWPN | None
    target_id: int


class FCPortCreate(FCPortEntry):
    id: Excluded = excluded_field()
    wwpn: Excluded = excluded_field()
    wwpn_b: Excluded = excluded_field()


class FCPortCreateArgs(BaseModel):
    fc_Port_create: FCPortCreate


class FCPortCreateResult(BaseModel):
    result: FCPortEntry


class FCPortUpdate(FCPortCreate, metaclass=ForUpdateMetaclass):
    pass


class FCPortUpdateArgs(BaseModel):
    id: int
    fc_Port_update: FCPortUpdate


class FCPortUpdateResult(BaseModel):
    result: FCPortEntry


class FCPortDeleteArgs(BaseModel):
    id: int


class FCPortDeleteResult(BaseModel):
    result: Literal[True]


class FCPortChoiceEntry(BaseModel):
    wwpn: WWPN | None
    wwpn_b: WWPN | None


class FCPortChoicesArgs(BaseModel):
    include_used: bool = True


class FCPortChoicesResult(BaseModel):
    result: Dict[FibreChannelPortAlias, FCPortChoiceEntry] = Field(examples=[
        {
            'fc0': {
                'wwpn': 'naa.2100001122334455',
                'wwpn_b': 'naa.210000AABBCCDDEEFF'
            },
            'fc0/1': {
                'wwpn': 'naa.2200001122334455',
                'wwpn_b': 'naa.220000AABBCCDDEEFF'
            },
        },
    ])
