#!/usr/bin/lua
require("LuaOpenPGP")

local function getSecretKey(path)
	print("========== READ SECRET KEY =============")
	local ok, val, err = readSecretKey(path);
	print(ok, ok==1 and "Success" or err);
	return val; 
end

local function getPublicKey(path)
	print("========== READ PUBLIC KEY =============")
	local ok, val, err = readPublicKey(path);
	print(ok, ok==1 and "Success" or err);
	return val 
end

local function getEncryptMsg(path, msg)
	print("========== Encrypt Message =============")
	local ok, val, err = encryptMsg(path, msg)
	print(ok, ok==1 and "Success" or err);
	return val
end 

local function getDecryptMsg(path, passphrase, msg)
	print("========== Decrypt Message =============")
	local ok, val, err = decryptMsg(path, passphrase, msg)
	print(ok, ok==1 and "Success" or err);
	return val
end

local function getSignMsg(path, passphrase, msg)
	print("========== Sign Message =============")
	local ok, val, err = signMsg(path, passphrase, msg)
	print(ok, ok==1 and "Success" or err);
	return val
end

local function getVerifyMsg(pubKey, text, sig)
	print("========== Verify Message =============")
	local ok, err = verifyMsg(pubKey, text, sig)
	print(ok, ok==1 and "Success" or err);
	return ok
end

local function getFingerprint_(key)
	print("========== Get fingerprint =============")
	local ok, fingerprint, err = getFingerprint(key);
	print(ok, ok==1 and fingerprint or err)
end

local rawMsg = "hello";
local passphrase = "123456789";
local secPath = "OpenPGP_demo-sec.asc";
local pubPath = "OpenPGP_demo-pub.asc";

local secKey = getSecretKey(secPath);
local pubKey = getPublicKey(pubPath);

local enMsg = getEncryptMsg(pubPath, rawMsg);
local decMsg = getDecryptMsg(secPath, passphrase, enMsg);

local sig = getSignMsg(secPath, passphrase, rawMsg);
local verify = getVerifyMsg(pubKey, rawMsg, sig);
local fingerprint = getFingerprint_(pubKey);
