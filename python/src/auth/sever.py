import jwt,datetime,os
from flask import Flask,request
from flask_mysqldb import MySQL

server=Flask(__name__)
mysql=MySQL(server)


#config
server.config["MYSQL_HOST"]=os.environ.get("MYSQL_HOST")
server.config["MYSQL_USER"]=os.environ.get("MYSQL_USER")
server.config["MYSQL_PASSWORD"]=os.environ.get("MYSQL_PASSWORD")
server.config["MYSQL_DB"]=os.environ.get("MYSQL_DB")
server.config["MYSQL_PORT"]=os.environ.get("MYSQL_PORT")

@server.route('/',methods=["POST"])
def login():
    auth=request.authorization
    if not auth:
        return "missing creds",401
    
    # check db for username and password
    cur =mysql.connection.cursor()
    res=cur.execute(
        "SELECT email,password WHERE email=%s",(auth.username,))
    
    if(res>0):
        user_row=cur.getchone()
        email=user_row[0]
        password=user_row[1]

        if(auth.username!=email or auth.password!=password):
            return 'invalid credentials',401
        else:
            createJWT(auth.username,os.environ.get("JWT_SECRET"),True)
    else:
        return 'invalid credentials',401
    
def createJWT(username,secret,isAdmin):
    return jwt.encode(
        {
            "username":username,
            "exp":datetime.datetime().now()+datetime.timedelta(days=1),
            "iat":datetime.datetime().utcnow(),
            "admin":isAdmin
        },
         secret,
         algorithm="HS256")

# This is hot config
# 0.0.0.0 tells ours flask app to listen all the public IP's
if __name__=='__main__':
    server.run(port=5000,host='0.0.0.0')

@server.route("/validate",methods=["POST"])
def validate():
    encoded_jwt=request.headers["Authorization"]

    if not encoded_jwt:
        return "missing crenetials",401
    

    # Authorization : <tyep> <tokem>
    # ex :- authorization: bearer jsi8uwu37e839932gdyhdu
    encoded_jwt=encoded_jwt.split(" ")[1]

    try:
        decoded=jwt.decode(encoded_jwt,os.environ.get("JWT_SECRET"),algorithms="HS256")
    except:
       return "not authorized",403

    return decoded,200