package org.zerock.api01.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(info())
                .addSecurityItem(securityRequirement())
                .components(components());
    }

    private Info info() {
        return new Info()
                .title("Boot API 01 Project Swagger");
    }

    private SecurityRequirement securityRequirement() {
        return new SecurityRequirement().addList("Authorization");
    }

    private Components components() {
        return new Components().addSecuritySchemes("Authorization", new SecurityScheme()
                .name("Authorization")
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
        );
    }


}
