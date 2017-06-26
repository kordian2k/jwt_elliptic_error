package someurl.jwt.error;


import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.rxjava.core.AbstractVerticle;
import io.vertx.rxjava.core.Vertx;
import io.vertx.rxjava.core.buffer.Buffer;
import io.vertx.rxjava.ext.auth.jwt.JWTAuth;
import rx.Single;

import java.io.File;
import java.io.IOException;

/**
 * Reproduces a validation error for JWT tokens when using vertx 3.4.2 and elliptic curve cryptography.
 *
 * @author Kordian2k
 */
public class Starter extends AbstractVerticle {
    private static final String DEFAULT_ALGORITHM = "ES512";//= "RS256";
    private static final Logger logger = LoggerFactory.getLogger(Starter.class.getName());
    private static final String VERTX_TOKEN_FILE = "jwt_vertx.txt";
    private static final String PYJWT_TOKEN_FILE = "jwt_pyjwt.txt";
    private static final String WORKDIR = "/example/";

    @Override
    public void start() throws Exception {
        final JWTAuth jwtAuth = JWTAuth.create(vertx, new JsonObject().put("keyStore",new JsonObject()
                .put("path", "jwt_keystore.jceks")
                .put("type", "jceks")
                .put("password", "password")));

        // Generate a token using vertx-auth-jwt and write it to file
        final JWTOptions jwtOptions = new JWTOptions().setExpiresInSeconds(3_600L).setAlgorithm(DEFAULT_ALGORITHM);
        final JsonObject claims = new JsonObject().put("username", "somebody").put("some", "payload");
        final String token = jwtAuth.generateToken(claims, jwtOptions);
        logger.info("Token by vertx-auth-jwt: " + token);

        // Write token to file, verify and construct a new token w/ pyJWT, verify the new token w/ vertx
        vertx.fileSystem().rxWriteFile(WORKDIR + VERTX_TOKEN_FILE, Buffer.buffer(token))
            .flatMap(v -> runPyJWT(vertx))
            .flatMap(integer -> compareTokens(vertx, jwtAuth))
            .subscribe(v -> logger.info("Passed! Stopping verticle.")
                    , err -> logger.fatal("Something went wrong: ", err));
    }

    private static Single<Integer> runPyJWT(Vertx vertx) {
        return vertx.rxExecuteBlocking(future -> {
            final ProcessBuilder pb = new ProcessBuilder("python", "pyjwt.py")
                    .directory(new File(WORKDIR)).inheritIO();
            try {
                switch (pb.start().waitFor()) {
                    case 0: future.complete(0); break;
                    case 1: future.fail(new IOException("IOException in python process.")); break;
                    case 2: logger.error("Decode exception in pyJWT while processing vertx JWT. " +
                                        "Continuing to read new token from pyJWT.");
                            future.complete(2);
                        break;
                    default: future.fail(new RuntimeException("Unkown exit code in python process."));
                }
            } catch (IOException | InterruptedException e) {
                logger.fatal("Could not run python process.");
                future.fail(e);
            }
        });
    }

    private static Single<JsonObject> compareTokens(Vertx vertx, JWTAuth jwtAuth) {
        return vertx.fileSystem().rxReadFile(PYJWT_TOKEN_FILE)
            .flatMap(buffer -> {
                final String token = buffer.getString(0, buffer.length() - 1, "UTF-8");
                logger.info("Token by pyJWT: " + token);
                return jwtAuth.rxAuthenticate(new JsonObject().put("jwt", token));
            }).flatMap(user -> {
                logger.info("PyJWT user principal: " + user.principal());
                return Single.just(user.principal());
            });
    }
}
