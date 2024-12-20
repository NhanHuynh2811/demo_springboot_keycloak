package com.example.demo_springboot_keycloak.service.keycloak;

import com.example.demo_springboot_keycloak.domain.entities.MsMUser;
import com.example.demo_springboot_keycloak.service.MsMUserService;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.springframework.stereotype.Component;

@Component
public class CustomUserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {
    private final KeycloakSession session;
    private final MsMUserService userService;

    public CustomUserStorageProvider(KeycloakSession session, MsMUserService userService) {
        this.session = session;
        this.userService = userService;
    }


    @Override
    public boolean supportsCredentialType(String credentialType) {
        if(CredentialModel.PASSWORD.equals(credentialType)) {
            UserModel user = session.getContext().getAuthenticationSession().getAuthenticatedUser();
            if (user != null && user.getFederationLink() != null) {
                // Federated users don't support passwords
                return false;
            }
            return true; // Support password for non-federated users
        }
        return false;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return false;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        return supportsCredentialType(input.getType());
        //return credentialService.verifyPassword(user.getUsername(), input.getChallengeResponse());
    }

    @Override
    public void close() {

    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String s) {
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realmModel, String username) {
        MsMUser msMUser = userService.findByUsername(username);
        if (msMUser == null) return null;

        return createKeycloakUser(realmModel, msMUser);
    }

    private UserModel createKeycloakUser(RealmModel realm, MsMUser user) {
        UserModel userModel = session.users().addUser(realm, user.getUsername());
        userModel.setEmail(user.getEmail());
        userModel.setEnabled(user.isEnabled());
        return userModel;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String s) {
        return null;
    }
}
