import sys
import base64
import binascii
import aws_session_pb2
from datetime import datetime
from ecdsa.util import sigencode_der, sigdecode_der
import ecdsa
from hashlib import sha256
import time
from google.protobuf.json_format import MessageToJson


def intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3

def get_region_public_key(sess1,sess2):

    if(sess1.session_pb.sign_key_id !=  sess2.session_pb.sign_key_id):
        return
    keys1 = sess1.get_verifying_keys()
    keys2 = sess2.get_verifying_keys()

    key = intersection(keys1, keys2)
    return (key[0].to_pem())
 
def pretty_print_buffer(buffer):
    print("length: ", len(buffer), "\nhex: ", binascii.hexlify(buffer,' '))

class AWS_Session:
    def __init__(self, session_type, session_pb):
        self.session_type = session_type
        self.session_pb = session_pb
       
    def SerializeToToken(self):
        a = self.session_pb.SerializeToString()
        a = self.session_type.to_bytes() + a
        a64 = base64.b64encode(a)
        return a64
    
    def pretty_print(self):
        print("type: ", self.session_type)
        print(MessageToJson(self.session_pb))

        print("creation time", datetime.fromtimestamp(self.session_pb.creation_unixtime))
    
    def update_time(self, time):
        self.session_pb.creation_unixtime = time
        return self.SerializeToToken()

class AWS_Session_V1(AWS_Session):
    def pretty_print(self):
         super().pretty_print()


class AWS_Session_V2(AWS_Session):


    def get_verifying_keys(self):
       
        curve = ecdsa.curves.NIST256p

        generator = curve.generator
        vks = ecdsa.VerifyingKey.from_public_key_recovery(self.session_pb.DER_Sig, self.session_pb.user.SerializeToString(), curve, sha256, sigdecode_der )
        return vks

    def get_signature(self):
        curve = ecdsa.curves.NIST256p

        generator = curve.generator
        r, s = ecdsa.util.sigdecode_der(self.session_pb.DER_Sig, generator.order())
        return r,s
    
    def pretty_print(self):
        super().pretty_print()
        r,s = self.get_signature()
        print("r: " , r, " s: ", s)
       

def parse_session(base64_session):
    session_hex = base64.b64decode(base64_session)
    type = session_hex[0]
    session_hex = session_hex[1:]

   
    match type:
        case 33:
            m = aws_session_pb2.SessionType33Message()
            m.ParseFromString(session_hex)
            sess = AWS_Session_V2(33, m)
        case 2: #also 2 for old types
            m = aws_session_pb2.SessionType33Message()
            m.ParseFromString(session_hex)
            sess = AWS_Session_V2(2, m)
        case 21:
            m = aws_session_pb2.SessionType21Message()
            m.ParseFromString(session_hex)
            sess = AWS_Session_V1(21, m) 
        case 23:
            m = aws_session_pb2.SessionType23Message()
            m.ParseFromString(session_hex)
            sess = AWS_Session_V1(23, m) 
        case _:
            print("unknown type")
        
    return sess


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sess = parse_session(sys.argv[1])
        sess.pretty_print() 
    

#basic tests

def test_parse_all_types():
    
    print("version 1 tokens")
    print("\ntype 21 test\n")
    #source: https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/ 
    session_type_21 = "FQoDYXdzEPP//////////wEaDPv5GPAhRW8pw6/nsiKsAZu7sZDCXPtEBEurxmvyV1r+nWy1I4VPbdIJV+iDnotwS3PKIyj+yDnOeigMf2yp9y2Dg9D7r51vWUyUQQfceZi9/8Ghy38RcOnWImhNdVP5zl1zh85FHz6ytePo+puHZwfTkuAQHj38gy6VF/14GU17qDcPTfjhbETGqEmh8QX6xfmWlO0ZrTmsAo4ZHav8yzbbl3oYdCLICOjMhOO1oY+B/DiURk3ZLPjaXyoo2Iql2QU="
    sess = parse_session(session_type_21)
    sess.pretty_print() 
    
    #source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/aws_iam 
    print("\ntype 23 test\n")
    session_type_23 = "FwoGZXIvYXdzEBAaDLHxhjed4A6ABQplMyKBAd0Jzohb7hRtcvWvjWSNw5bVcn5al0jGu9Cl7W2ijDztOnmLZICjbsFBYgO7mt2J1AM9CO0nrL9qBatm9+ytKde5MXuKyzMGY6J8YDLoXU625FQKpnGXelSQxA1mYI/VOjaSa2MP4gPZsgOBjyOuiRxUKmkgYglbzl8sGYco9KWSNyjK5/aKBjIoKnYXwjdTkOt7/Bw6HMETrjPUPyHStdSfCjt4IwGvu2ox5Xo8VHAp5g=="
    sess = parse_session(session_type_23)
    sess.pretty_print()

    #source: https://stackoverflow.com/questions/58140818/decoding-an-aws-session-token/58195241#58195241 
    print("\ntype 2 test\n")
    session_type_2 = "AgoJb3JpZ2luX2VjEKH//////////wEaCXVzLWVhc3QtMiJHMEUCIQDDTKUnIQtIcztLVmpTsif9b9rj5yUOiBgfPNN3z16S6gIgUAlRFD8V9bpVokR0sqrtxN/5uPtaLf4vHGPAtUokj/kqpgUIehABGgwyNDcyMjQ3MzEwMjEiDE7afe4LMcTOdqF3niqDBbwZENnBEw3XyIdGz1AEPVY51gZ0KxkC7YgoAxpZVedZZUbIeAiGy+Ez2PtTzsVhO1WPiM5DqwTqb3/iuV2XsTXGf43qpTc2WsYypFUI51scF1J+pSGT58yAayTf5wwPi9I1kFWiBcDpuyemLwI2yfZB8hIuAvdr0MW6a7GVHR93xDfsx0T7aCFqZriUQTOpc9clpkQfygdhf7mHeYdMnD/HthZCh3mllS4I86Zzjr8wIypCqrV0A2OhVVvsLddjF8WF4WS0WhNEEQHoUs/jMkDjnrcvPBIeuU/hE2x+UfECmH5vDs0QarfsHR1HiLVL+EghINNF9eG4CzpVu0FBz8meJhPEJLlQMK9MdZ7ZGgtx7ZzT/7a/azoCpriOK9KganXsMfHbwLqnR96bXEC3ebFYtL638y25KZyn7rL/z5Ise/D5KjihQOuuRoxufgUWKoi6Or0r56bSpLhq7KCd0ZUweoKKvX/9RLF2YU0h+FYV4NRxar93jzKEYX63so/gxCaWWb7gRde/qca3fEZHHh0I26/DflrvWar6HDHu3Ee7aYJB/m5n4u1ko6SRvAdwmQ/hn1ttDgvUSpVq28IyxR4Ic9cBaS81ohRInM7i6NTSGHhpd6ij0l0F1Br8Vtr5UJe96xK7aNir3sspYqrSzd6y1DO6fnZKVaFpWDnWo4/SCdSp3F9bM4Q+GNICaT9Rcvyx1nJgofuqY4gdHdxv1PoIL8KEXz72U8aZ/immlhZ5kNrc/aM5KEJ4weE04mZ4u1t3GmN5xLFd7wqOCPUvrzamiEy4GMtm+kBF5rsa+eVRp+YpN2R6CsUpCqw8EEhE3w6RMV578Ah3sO0nBwXQXNQ7nKQwxoa57AU6tAHGr89nNR/Br3UahFBK5o9mQ297nbWB5C6PqCSShsheXzkJww0OdqMwmZgIfvikqnWNZC5KrfobiSancqCXKIRbuLtWcWT6+F9Q+eJQ50Rj1ctdN18H84cfQZYNjHRQVf7iTTcgfq8oqlJtmEavs8T2rvp3a9gp1QQEwjIHdCUQJRwM8h2RYFvLd6s48/XT9sxQj8OAmq8q/gw6/fOiRPFj9yq/Pw38IusTE0MFFwgAJWgUSAo="
    sess = parse_session(session_type_2)
    sess.pretty_print()

    #source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/specifics/aws_iam
    print("\ntype 33 test\n")
    session_type_33 = "IQoJb3JpZ2luX2VjEDoaCXVzLWVhc3QtMiJIMEYCIQDQh4gelDqno96q39RwiPT5x7K7SyVOSmeDpUMd9SthWAIhAP5tT81Cb+Rb2zN85delmYB4KECmW1uL7Tr36C/M2GaJKr0DCKP//////////wEQARoMNjY2MzU5NzY0NTI4Igyu9F2yAqZN3dG0q9YqkQMVrg/4mCJjDxg0QmplU581Z2P8LGhGfr9vgei6SaONhhfks5Kt9Ikbh61G9UiQ3SXgPLbHjOfTUueaIIcBz1Y3LcW+WajtfsGfB8CqT76lkJLtkvl+1KjSCVn6k+/K/iWgr3Zc1Ej+qT2djTH4x1OWFNS6i6iCtlUy/Z6i3P2fziHGsEmafkH3ict+07dFb3DA2aRnUhnaCHfQDNd/5ub70oILwB4UgtgGNkbM9SE/NxKgPZY9qIktYifqcgfDyYMYHlvY9XEc0UT2jfaQKDYVgMCdsdsW5mkoBYzLRisQhKxjfwaBpkRtdW8dEHFAG04eV4JSAbOSat3bgUwahATGizOdsMz/qhnS9qzShQGgSR6OU6pDDUtuHCGh0sgwrjsZ+bGDfzkw5Sy3JhjQpozfinCsAmDZ1t3nX6llw9OR9B2mdDHCeccsWGwjIvmprs21FtgjDuKGzaAET6HgQAR+pkFUgxBWVmZArtck1ziG21FEN8pFR75rOgxSkQ3yEZeDZkIIZ/aJnABGvbC3Fbq9ATD6ycuKBjqlAaGPeFKzdCR1dBh4sHQVHejXNegWWZV72n4MLyZx2FE9wLUfPGXXW+pYZg4SySvN0Z4OnGoYdlO/pjKvdRa507mSD8N8EhkwgpJMatFobJb0hsz7GY5flutVSkDfBDYkU91vpl7YCJ5rlvuR0I6iWe+K7smYj5hzm16YokWsRQ4EeWHo0peEJuqTZrZt/U4gHVsFpG44V8Yb6iRdZL78E+5xcgjeFw=="
    sess = parse_session(session_type_33)
    sess.pretty_print()


#test_parse_all_types()

# extract public key

def test_extract_public_key(token1,token2):
    sess1 = parse_session(token1)
    sess1.pretty_print()

    sess2 = parse_session(token2)
    sess2.pretty_print()

    print(get_region_public_key(sess1,sess2))

#test_extract_public_key(session_us_west_2_1,session_us_west_2_2)
# session_us_west_2_1 intersection session_us_west_2_2 11.7.24
#key_us_west_1 = b'-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzuplh/vDM621Y4qNPmaVUM8TfyMstLGlu/9wT3M\nizt8SCDxslIHbNYu36khLM7mxqocy7jU3tJfNZKg+X2p3g==\n-----END PUBLIC KEY-----\n'

def test_udpate_time():
    session_type_33 = "IQoJb3JpZ2luX2VjEDoaCXVzLWVhc3QtMiJIMEYCIQDQh4gelDqno96q39RwiPT5x7K7SyVOSmeDpUMd9SthWAIhAP5tT81Cb+Rb2zN85delmYB4KECmW1uL7Tr36C/M2GaJKr0DCKP//////////wEQARoMNjY2MzU5NzY0NTI4Igyu9F2yAqZN3dG0q9YqkQMVrg/4mCJjDxg0QmplU581Z2P8LGhGfr9vgei6SaONhhfks5Kt9Ikbh61G9UiQ3SXgPLbHjOfTUueaIIcBz1Y3LcW+WajtfsGfB8CqT76lkJLtkvl+1KjSCVn6k+/K/iWgr3Zc1Ej+qT2djTH4x1OWFNS6i6iCtlUy/Z6i3P2fziHGsEmafkH3ict+07dFb3DA2aRnUhnaCHfQDNd/5ub70oILwB4UgtgGNkbM9SE/NxKgPZY9qIktYifqcgfDyYMYHlvY9XEc0UT2jfaQKDYVgMCdsdsW5mkoBYzLRisQhKxjfwaBpkRtdW8dEHFAG04eV4JSAbOSat3bgUwahATGizOdsMz/qhnS9qzShQGgSR6OU6pDDUtuHCGh0sgwrjsZ+bGDfzkw5Sy3JhjQpozfinCsAmDZ1t3nX6llw9OR9B2mdDHCeccsWGwjIvmprs21FtgjDuKGzaAET6HgQAR+pkFUgxBWVmZArtck1ziG21FEN8pFR75rOgxSkQ3yEZeDZkIIZ/aJnABGvbC3Fbq9ATD6ycuKBjqlAaGPeFKzdCR1dBh4sHQVHejXNegWWZV72n4MLyZx2FE9wLUfPGXXW+pYZg4SySvN0Z4OnGoYdlO/pjKvdRa507mSD8N8EhkwgpJMatFobJb0hsz7GY5flutVSkDfBDYkU91vpl7YCJ5rlvuR0I6iWe+K7smYj5hzm16YokWsRQ4EeWHo0peEJuqTZrZt/U4gHVsFpG44V8Yb6iRdZL78E+5xcgjeFw=="
    sess = parse_session(session_type_33)
    print("before")
    sess.pretty_print()

    epoch_time = int(time.time())
    sess.update_time(epoch_time)
    print("after")
    sess.pretty_print()



