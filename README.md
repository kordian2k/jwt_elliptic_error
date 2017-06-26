# jwt_elliptic_error
Compares tokens constructed using elliptic curve cryptography with PyJWT resp. Eclipse Vert.x.

`mvn package` constructs a docker image based on Debian Jesse with Pyhton 3.6 and OpenJDK 8. Then run
```
docker run -it <image_id>
```
# Requirements
* docker
* For the maven docker plugins to succeed the user running maven must have the rights to run docker, e.g., by putting the user running maven into the docker group.
