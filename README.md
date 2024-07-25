# AWS STS Token Decoder

AWS STS Token Decoder is a Python application to decode and encode AWS Session Tokens.


## Compiling protobuf

We already compiled the protobuf definitions in the /proto folder into a python script aws_session_pb2.py. <br>
If you wish to edit the .proto file and compile a python file you can use the following command

```
protoc -I=./proto --python_out=. Aws_session.proto

```


## Usage example
parse a token

```
% python3 STS-session.py "IQoJb3JpZ2luX2VjEDoaCXVzLWVhc3QtMiJIMEYCIQDQh4gelDqno96q39RwiPT5x7K7SyVOSmeDpUMd9SthWAIhAP5tT81Cb+Rb2zN85delmYB4KECmW1uL7Tr36C/M2GaJKr0DCKP//////////wEQARoMNjY2MzU5NzY0NTI4Igyu9F2yAqZN3dG0q9YqkQMVrg/4mCJjDxg0QmplU581Z2P8LGhGfr9vgei6SaONhhfks5Kt9Ikbh61G9UiQ3SXgPLbHjOfTUueaIIcBz1Y3LcW+WajtfsGfB8CqT76lkJLtkvl+1KjSCVn6k+/K/iWgr3Zc1Ej+qT2djTH4x1OWFNS6i6iCtlUy/Z6i3P2fziHGsEmafkH3ict+07dFb3DA2aRnUhnaCHfQDNd/5ub70oILwB4UgtgGNkbM9SE/NxKgPZY9qIktYifqcgfDyYMYHlvY9XEc0UT2jfaQKDYVgMCdsdsW5mkoBYzLRisQhKxjfwaBpkRtdW8dEHFAG04eV4JSAbOSat3bgUwahATGizOdsMz/qhnS9qzShQGgSR6OU6pDDUtuHCGh0sgwrjsZ+bGDfzkw5Sy3JhjQpozfinCsAmDZ1t3nX6llw9OR9B2mdDHCeccsWGwjIvmprs21FtgjDuKGzaAET6HgQAR+pkFUgxBWVmZArtck1ziG21FEN8pFR75rOgxSkQ3yEZeDZkIIZ/aJnABGvbC3Fbq9ATD6ycuKBjqlAaGPeFKzdCR1dBh4sHQVHejXNegWWZV72n4MLyZx2FE9wLUfPGXXW+pYZg4SySvN0Z4OnGoYdlO/pjKvdRa507mSD8N8EhkwgpJMatFobJb0hsz7GY5flutVSkDfBDYkU91vpl7YCJ5rlvuR0I6iWe+K7smYj5hzm16YokWsRQ4EeWHo0peEJuqTZrZt/U4gHVsFpG44V8Yb6iRdZL78E+5xcgjeFw=="

type:  33
{
  "name": "origin_ec",
  "signKeyId": "58",
  "region": "us-east-2",
  "DERSig": "MEYCIQDQh4gelDqno96q39RwiPT5x7K7SyVOSmeDpUMd9SthWAIhAP5tT81Cb+Rb2zN85delmYB4KECmW1uL7Tr36C/M2GaJ",
  "user": {
    "encryptKeyId": "-93",
    "someId": "1",
    "accountId": "666359764528",
    "IV": "rvRdsgKmTd3RtKvW",
    "userEncryptedData": "Fa4P+JgiYw8YNEJqZVOfNWdj/CxoRn6/b4HoukmjjYYX5LOSrfSJG4etRvVIkN0l4Dy2x4zn01LnmiCHAc9WNy3Fvlmo7X7BnwfAqk++pZCS7ZL5ftSo0glZ+pPvyv4loK92XNRI/qk9nY0x+MdTlhTUuouogrZVMv2eotz9n84hxrBJmn5B94nLftO3RW9wwNmkZ1IZ2gh30AzXf+bm+9KCC8AeFILYBjZGzPUhPzcSoD2WPaiJLWIn6nIHw8mDGB5b2PVxHNFE9o32kCg2FYDAnbHbFuZpKAWMy0YrEISsY38GgaZEbXVvHRBxQBtOHleCUgGzkmrd24FMGoQExosznbDM/6oZ0vas0oUBoEkejlOqQw1LbhwhodLIMK47Gfmxg385MOUstyYY0KaM34pwrAJg2dbd51+pZcPTkfQdpnQxwnnHLFhsIyL5qa7NtRbYIw7ihs2gBE+h4EAEfqZBVIMQVlZmQK7XJNc4httRRDfKRUe+azoMUpEN8hGXg2ZCCGf2iZwARr2wtxW6vQE="
  },
  "creationUnixtime": 1632822522,
  "auxData": "oY94UrN0JHV0GHiwdBUd6Nc16BZZlXvafgwvJnHYUT3AtR88Zddb6lhmDhLJK83Rng6cahh2U7+mMq91FrnTuZIPw3wSGTCCkkxq0WhslvSGzPsZjl+W61VKQN8ENiRT3W+mXtgInmuW+5HQjqJZ74ruyZiPmHObXpiiRaxFDgR5YejSl4Qm6pNmtm39TiAdWwWkbjhXxhvqJF1kvvwT7nFyCN4X"
}
creation time 2021-09-28 12:48:42
r:  94320536320976402567647841358238654142521339401152461683428052318097085522264  s:  115080600641957610719224864062596448685741805574002579554501035948511143159433
```

recover the current public key of the specified AWS region
```
scripts % ./recover_region_public_key.sh us-east-2
recover the current public key of the specified AWS region
returns (key id, public key)
(-17, b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+m4W7GdxDVv5kg9CqspDcvD3aQKlIZ1Y6TSRnA0u\ndcrTAGDAZMjGqZ7ZwAvdXu4t94rv2T0ndvZHv4kRg6jboA==\n-----END PUBLIC KEY-----\n')
```
