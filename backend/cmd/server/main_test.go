package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerUnconfiguredErrorAndRoleBasedAccessControl(t *testing.T) {
	srv := &Server{
		configPath:  "../../../config/organization.json",
		seedPath:    "../../../config/demo_seed.json",
		frontendDir: "../../../frontend",
		roleTokens:  defaultRoleTokens(),
	}

	// 1. When unconfigured, /api/v1/state returns configured=false
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/state", nil)
	rec1 := httptest.NewRecorder()
	srv.handleState(rec1, req1)
	var stateResp map[string]any
	_ = json.Unmarshal(rec1.Body.Bytes(), &stateResp)
	if stateResp["configured"] != false || stateResp["setup_error"] == "" {
		t.Fatalf("expected unconfigured state with actionable setup_error, got %+v", stateResp)
	}

	// 2. Load config/organization.json
	reqLoad := httptest.NewRequest(http.MethodPost, "/api/v1/config/load-file", nil)
	recLoad := httptest.NewRecorder()
	srv.handleLoadConfigFile(recLoad, reqLoad)
	if recLoad.Code != http.StatusOK {
		t.Fatalf("expected 200 OK loading config/organization.json, got %d", recLoad.Code)
	}

	// 3. HACKER TEST: A citizen/giver (or attacker without valid token) tries to call /api/v1/config
	//    or approve a milestone directly via API -> MUST BE BLOCKED with 403 Forbidden!
	hackCfg := httptest.NewRequest(http.MethodPost, "/api/v1/config", bytes.NewReader([]byte(`{"organization_name":"Hacked"}`)))
	hackCfg.Header.Set("X-Role", RoleGiver)
	recHack1 := httptest.NewRecorder()
	srv.handleUpdateConfig(recHack1, hackCfg)
	if recHack1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when citizen tries to modify config, got %d", recHack1.Code)
	}

	// Hacker claims to be "committee" in X-Role header, but lacks valid X-Role-Token -> 403 Forbidden!
	spoofApprove := httptest.NewRequest(http.MethodPost, "/api/v1/project/milestone",
		bytes.NewReader([]byte(`{"project_id":"proj-solar-lighting-001","milestone_idx":0,"action":"approve"}`)))
	spoofApprove.Header.Set("X-Role", RoleCommittee)
	spoofApprove.Header.Set("X-Role-Token", "wrong-hacker-token")
	recHack2 := httptest.NewRecorder()
	srv.handleMilestoneAction(recHack2, spoofApprove)
	if recHack2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when attacker spoofs committee role without token, got %d", recHack2.Code)
	}

	// 4. SEPARATION OF DUTIES: Even an authenticated SysAdmin ("sysadmin-demo-token") CANNOT approve a milestone or move funds!
	sysAdminApprove := httptest.NewRequest(http.MethodPost, "/api/v1/project/milestone",
		bytes.NewReader([]byte(`{"project_id":"proj-solar-lighting-001","milestone_idx":0,"action":"approve"}`)))
	sysAdminApprove.Header.Set("X-Role", RoleSysAdmin)
	sysAdminApprove.Header.Set("X-Role-Token", "sysadmin-demo-token")
	recSys := httptest.NewRecorder()
	srv.handleMilestoneAction(recSys, sysAdminApprove)
	if recSys.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when SysAdmin tries to approve milestone funds, got %d", recSys.Code)
	}

	// 5. Authenticated SysAdmin CAN update organization config and read tech-support diagnostics
	sysStateReq := httptest.NewRequest(http.MethodGet, "/api/v1/state", nil)
	sysStateReq.Header.Set("X-Role", RoleSysAdmin)
	sysStateReq.Header.Set("X-Role-Token", "sysadmin-demo-token")
	recSysState := httptest.NewRecorder()
	srv.handleState(recSysState, sysStateReq)
	var sysPayload map[string]any
	_ = json.Unmarshal(recSysState.Body.Bytes(), &sysPayload)
	if sysPayload["sysadmin_diagnostics"] == nil {
		t.Fatal("expected authenticated SysAdmin to receive sysadmin_diagnostics")
	}

	// 6. Public Citizen /api/v1/state response MUST NOT contain sysadmin_diagnostics or internal committee_account keys!
	pubStateReq := httptest.NewRequest(http.MethodGet, "/api/v1/state", nil)
	recPubState := httptest.NewRecorder()
	srv.handleState(recPubState, pubStateReq)
	var pubPayload map[string]any
	_ = json.Unmarshal(recPubState.Body.Bytes(), &pubPayload)
	if pubPayload["sysadmin_diagnostics"] != nil {
		t.Fatal("public citizen response must not leak sysadmin_diagnostics")
	}

	// 7. Full Subasta lifecycle (bid -> settle -> deliver_and_claim) requires a verified citizen account!
	// Unauthenticated visitor trying to bid without X-Citizen-Token -> MUST be rejected with 403 Forbidden!
	unauthBidReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"place_bid","bidder":"Vecina Maria","amount":55}`)))
	recUnauthBid := httptest.NewRecorder()
	srv.handleSubastaAction(recUnauthBid, unauthBidReq)
	if recUnauthBid.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when unverified visitor tries to bid, got %d", recUnauthBid.Code)
	}

	// Register Vecina Maria's verified citizen account and obtain X-Citizen-Token
	citAuthReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"citizen_auth","role":"citizen","credential_id":"Vecina Maria","token":"4829"}`)))
	recCitAuth := httptest.NewRecorder()
	srv.handleAuthLogin(recCitAuth, citAuthReq)
	var citAuthResp map[string]any
	_ = json.Unmarshal(recCitAuth.Body.Bytes(), &citAuthResp)
	citTok, _ := citAuthResp["citizen_token"].(string)
	if citTok == "" {
		t.Fatalf("expected non-empty citizen_token from citizen_auth, got %+v", citAuthResp)
	}

	bidReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"place_bid","bidder":"Vecina Maria","amount":55}`)))
	bidReq.Header.Set("X-Citizen-Token", citTok)
	srv.handleSubastaAction(httptest.NewRecorder(), bidReq)

	settleReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"settle"}`)))
	settleReq.Header.Set("X-Role", RoleCommittee)
	settleReq.Header.Set("X-Role-Token", "committee-demo-token")
	srv.handleSubastaAction(httptest.NewRecorder(), settleReq)

	// Committee submits physical delivery proof (money is still locked until Winning Citizen confirms!)
	deliverReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"submit_delivery"}`)))
	deliverReq.Header.Set("X-Role", RoleCommittee)
	deliverReq.Header.Set("X-Role-Token", "committee-demo-token")
	srv.handleSubastaAction(httptest.NewRecorder(), deliverReq)

	// Non-winning citizen CANNOT confirm receipt on behalf of Vecina Maria
	wrongBuyerReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"confirm_receipt","bidder":"Impostor"}`)))
	wrongBuyerReq.Header.Set("X-Citizen-Token", citTok)
	recWrongBuyer := httptest.NewRecorder()
	srv.handleSubastaAction(recWrongBuyer, wrongBuyerReq)
	if recWrongBuyer.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when non-winner tries to confirm receipt, got %d", recWrongBuyer.Code)
	}

	// Winning citizen ("Vecina Maria") confirms receiving the item -> releases payment to Committee Fund!
	confirmReq := httptest.NewRequest(http.MethodPost, "/api/v1/subasta",
		bytes.NewReader([]byte(`{"action":"confirm_receipt","bidder":"Vecina Maria"}`)))
	confirmReq.Header.Set("X-Citizen-Token", citTok)
	recConfirm := httptest.NewRecorder()
	srv.handleSubastaAction(recConfirm, confirmReq)
	if recConfirm.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when winner confirms receipt, got %d: %s", recConfirm.Code, recConfirm.Body.String())
	}

	stateAfterClaim := httptest.NewRecorder()
	srv.handleState(stateAfterClaim, httptest.NewRequest(http.MethodGet, "/api/v1/state", nil))
	var afterClaimJSON map[string]any
	if err := json.Unmarshal(stateAfterClaim.Body.Bytes(), &afterClaimJSON); err != nil {
		t.Fatalf("expected valid JSON from /api/v1/state after deliver_and_claim, got err=%v body=%s", err, stateAfterClaim.Body.String())
	}

	// 8. /api/v1/auth/login rejects wrong password OR missing 2FA with 403, and unlocks with Factor 1 + Factor 2 (2FA)
	badLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"role":"committee","token":"wrong-password"}`)))
	recBadLogin := httptest.NewRecorder()
	srv.handleAuthLogin(recBadLogin, badLogin)
	if recBadLogin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on invalid login token, got %d", recBadLogin.Code)
	}

	// Correct SysAdmin password but missing 2FA code -> MUST be rejected with 403 Forbidden!
	missing2FA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"token","role":"all","token":"sysadmin-demo-token"}`)))
	recMissing2FA := httptest.NewRecorder()
	srv.handleAuthLogin(recMissing2FA, missing2FA)
	if recMissing2FA.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when SysAdmin/All login is missing 2FA code, got %d", recMissing2FA.Code)
	}

	// Correct SysAdmin password + valid 2FA code (135790) -> 200 OK
	okLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"token","role":"all","token":"sysadmin-demo-token","two_fa_code":"135790"}`)))
	recOkLogin := httptest.NewRecorder()
	srv.handleAuthLogin(recOkLogin, okLogin)
	if recOkLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on master sysadmin login with 2FA, got %d", recOkLogin.Code)
	}

	// WebAuthn Passkey registration (requires Committee token + Committee 2FA code 246810) + passwordless Passkey login
	regPasskey := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"passkey_register","role":"committee","token":"committee-demo-token","two_fa_code":"246810","credential_id":"webauthn-cred-001"}`)))
	recRegPasskey := httptest.NewRecorder()
	srv.handleAuthLogin(recRegPasskey, regPasskey)
	if recRegPasskey.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on passkey registration with 2FA, got %d", recRegPasskey.Code)
	}

	loginPasskey := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"passkey_login","credential_id":"webauthn-cred-001"}`)))
	recLoginPasskey := httptest.NewRecorder()
	srv.handleAuthLogin(recLoginPasskey, loginPasskey)
	if recLoginPasskey.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on WebAuthn passkey login, got %d", recLoginPasskey.Code)
	}

	// Cloudflare Zero Trust Access SSO header verification
	cfLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"cloudflare_sso"}`)))
	cfLogin.Header.Set("Cf-Access-Authenticated-User-Email", "admin@waystobuildit.com")
	cfLogin.Header.Set("Cf-Access-Jwt-Assertion", "eyJhbGciOiJSUzI1NiJ9.cf_zero_trust_jwt")
	recCFLogin := httptest.NewRecorder()
	srv.handleAuthLogin(recCFLogin, cfLogin)
	if recCFLogin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on Cloudflare Zero Trust SSO login, got %d", recCFLogin.Code)
	}

	// Unauthenticated /api/v1/demo/reset is blocked with 403 Forbidden
	unauthReset := httptest.NewRequest(http.MethodPost, "/api/v1/demo/reset", nil)
	recUnauthReset := httptest.NewRecorder()
	srv.handleDemoReset(recUnauthReset, unauthReset)
	if recUnauthReset.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on unauthenticated demo reset, got %d", recUnauthReset.Code)
	}

	// Unauthenticated or Committee-authenticated /api/v1/testnet/verify-tx is blocked with 403 Forbidden (ONLY SysAdmin allowed!)
	unauthTestnet := httptest.NewRequest(http.MethodPost, "/api/v1/testnet/verify-tx",
		bytes.NewReader([]byte(`{"amount_ada":100}`)))
	unauthTestnet.Header.Set("X-Role", RoleCommittee)
	unauthTestnet.Header.Set("X-Role-Token", "committee-demo-token")
	recUnauthTestnet := httptest.NewRecorder()
	srv.handleTestnetVerifyTx(recUnauthTestnet, unauthTestnet)
	if recUnauthTestnet.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when Committee calls /api/v1/testnet/verify-tx (SysAdmin only), got %d", recUnauthTestnet.Code)
	}

	// Citizen account registration & anti-bot PIN verification
	citReg := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"citizen_auth","role":"citizen","credential_id":"Vecina Maria","token":"4829"}`)))
	recCitReg := httptest.NewRecorder()
	srv.handleAuthLogin(recCitReg, citReg)
	if recCitReg.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on citizen account creation, got %d", recCitReg.Code)
	}

	citWrongPIN := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		bytes.NewReader([]byte(`{"method":"citizen_auth","role":"citizen","credential_id":"Vecina Maria","token":"0000"}`)))
	recCitWrong := httptest.NewRecorder()
	srv.handleAuthLogin(recCitWrong, citWrongPIN)
	if recCitWrong.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on wrong citizen PIN, got %d", recCitWrong.Code)
	}
}
