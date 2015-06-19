# This is as sketch of how to decaffeinate Curve25519

F = GF(2^255-19)
d = -121665
M = EllipticCurve(F,[0,2-4*d,0,1,0])

def maybe(): return randint(0,1)

def qpositive(x):
    return int(x) <= (2^255-19-1)/2

def M_to_E(P):
    # P must be even
    (x,y) = P.xy()
    assert x.is_square()
    
    s = sqrt(x)
    if s == 0: t = 1
    else: t = y/s
    
    X,Y = 2*s / (1+s^2), (1-s^2) / t
    if maybe(): X,Y = -X,-Y
    if maybe(): X,Y = Y,-X
    # OK, have point in ed
    return X,Y
    

def decaf_encode_from_E(X,Y):
    assert X^2 + Y^2 == 1 + d*X^2*Y^2
    if not qpositive(X*Y): X,Y = Y,-X
    assert qpositive(X*Y)
    
    assert (1-X^2).is_square()
    sx = sqrt(1-X^2)
    tos = -2*sx/X/Y
    if not qpositive(tos): sx = -sx
    s = (1 + sx) / X
    if not qpositive(s): s = -s
    
    return s
    
def is_rotation((X,Y),(x,y)):
    return x*Y == X*y or x*X == -y*Y
    
def decaf_decode_to_E(s):
    assert qpositive(s)
    t = sqrt(s^4 + (2-4*d)*s^2 + 1)
    if not qpositive(t/s): t = -t
    X,Y = 2*s / (1+s^2), (1-s^2) / t
    assert qpositive(X*Y)
    return X,Y

def test():
    P = 2*M.random_point()
    X,Y = M_to_E(P)
    s = decaf_encode_from_E(X,Y)
    XX,YY = decaf_decode_to_E(s)
    assert is_rotation((X,Y),(XX,YY))


    