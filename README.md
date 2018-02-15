# AdminServer

This is an example server implementation which:
- Was going to uses MongoDB for authentication
- Load test purpose multiple client stacks on fly
- create MTikClient ip:port
- create TMongoClient ip:port
- interact with multiple Mongos or Mikrotiks

Mongo commands:
- TMongoClient #id 
  - insert key col=data[,col2=data2,..]
  - remove key
  - select key col=data[,col2=data2,..] 

MikroTik Commands:
- MTIkClient #id
  - login user=user password=password
  - /mikrotikdata (refer to mikrotik API docs how to craft these) 
