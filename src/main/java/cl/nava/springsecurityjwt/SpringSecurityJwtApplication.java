package cl.nava.springsecurityjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import cl.nava.springsecurityjwt.config.DotenvInitializer;

@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(SpringSecurityJwtApplication.class);
        app.addInitializers(new DotenvInitializer());
        app.run(args);
    }
}