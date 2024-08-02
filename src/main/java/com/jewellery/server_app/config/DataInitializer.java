package com.jewellery.server_app.config;

import com.jewellery.server_app.model.ERole;
import com.jewellery.server_app.model.Role;
import com.jewellery.server_app.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        // for (ERole eRole : ERole.values()) {
        //     if (!roleRepository.findByName(eRole.name()).isPresent()) {
        //         Role role = new Role();
        //         role.setName(eRole.name());
        //         roleRepository.save(role);
        //     }
        // }
    }
}
