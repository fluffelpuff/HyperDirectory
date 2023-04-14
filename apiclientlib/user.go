package main

// Wird verwndet um einen neuen Benutzer zu erstellen
func (obj *RpcClient) CreateNewUser(email_address string, password string) {

}

// Wird verwendet um einen neuen Benutzer zu erstellen (leitet eine fertige Registrationanfrage weiter)
func (obj *RpcClient) CreateNewUserForward(cs_owner_public_key string, cs_owner_signature string, enc_user_password string, mkey_sig string, enc_master_key string, pmaster_key string, email_adr string, gender string, first_names []string, last_names []string) {

}

// Wird verwendet um einen neue Benutzer Sitzung zu erstellen
func (obj *RpcClient) CreateNewLoginProcess(email_address string, password string) {

}

// Wird verwendet um eine neue Benutzer Sitzung anhand der
func (obj *RpcClient) CreateNewLoginProcessForward(plc_key string, pcl_sig string, otk_pkey string) {

}
