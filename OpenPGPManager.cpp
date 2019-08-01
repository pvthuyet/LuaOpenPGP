/*
 * WherzatPGP.cpp
 *
 *  Created on: Jul 8, 2019
 *      Author: novel
 */

#include "OpenPGPManager.h"

#include <fstream>
#include <string>
#include <iostream>

using namespace std;

OpenPGPManager::OpenPGPManager() {
	// TODO Auto-generated constructor stub

}

OpenPGPManager::~OpenPGPManager() {
	// TODO Auto-generated destructor stub
}

OpenPGP::SecretKey OpenPGPManager::loadSecretKey(const std::string& secPath) const {
	std::ifstream ifs(secPath, std::ifstream::in);
	OpenPGP::SecretKey key(ifs);
	ifs.close();

	return key;
}

OpenPGP::PublicKey OpenPGPManager::loadPublicKey(const std::string& pubPath) const {
	std::ifstream ifs(pubPath, std::ifstream::in);
	OpenPGP::PublicKey key(ifs);
	ifs.close();

	return key;
}

bool OpenPGPManager::readPublicKey(const std::string& pubPath, std::string& outMsg, std::string& outErrMsg) const {
	try {
		OpenPGP::PublicKey key = loadPublicKey(pubPath);
		if (!key.meaningful()) {
			return false;
		}
		outMsg = key.write();

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::readSecretKey(const std::string& secPath, std::string& outMsg, std::string& outErrMsg) const {
	try {
		OpenPGP::SecretKey key = loadSecretKey(secPath);
		if (!key.meaningful()) {
			return false;
		}
		outMsg = key.write();

	} catch (const std::exception& e) {
		outErrMsg =  e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::decryptMsg(const std::string& secPath, const std::string& passphrase, const std::string& data, std::string& outMsg, std::string& outErrMsg) const {
	try {
		// Load private key and verify
		OpenPGP::SecretKey key = loadSecretKey(secPath);
		if (!key.meaningful()) {
			return false;
		}

		// Encrypt message data
		OpenPGP::Message encMsg(data);
		if (!encMsg.meaningful()) {
			return false;
		}

		OpenPGP::Message decMsg = OpenPGP::Decrypt::pka(key, passphrase, encMsg);
		if (!decMsg.meaningful()) {
			return false;
		}

		outMsg = decMsg.write();

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::encryptMsg(const std::string& pubPath, const std::string& data, std::string& outMsg, std::string& outErrMsg) const {
	try {
		OpenPGP::Encrypt::Args args("", data);
		if (!args.valid()) {
			return false;
		}

		// encrypt messgae
		OpenPGP::PublicKey key = loadPublicKey(pubPath);
		if (!key.meaningful()) {
			return false;
		}

		OpenPGP::Message encMsg = OpenPGP::Encrypt::pka(args, key);
		if (!encMsg.meaningful()) {
			return false;
		}

		outMsg = encMsg.write();

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::signMsg(const std::string& secPath, const std::string& passphrase, const std::string& data, std::string& outMsg, std::string& outErrMsg) const {
	try {
		OpenPGP::SecretKey key = loadSecretKey(secPath);
		if (!key.meaningful()) {
			return false;
		}

		OpenPGP::Sign::Args args(key, passphrase);
		if (!args.valid()) {
			return false;
		}

		OpenPGP::DetachedSignature sign = OpenPGP::Sign::detached_signature(args, data);
		if (!sign.meaningful()) {
			return false;
		}

		outMsg = sign.write();

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::verifyMsg(const std::string& pubKey, const std::string& data, const std::string& sigData, std::string& outErrMsg) const {
	try {
		OpenPGP::PublicKey key(pubKey);
		if (!key.meaningful()) {
			return false;
		}

		OpenPGP::DetachedSignature sig(sigData);
		if (!sig.meaningful()) {
			return false;
		}

		if (OpenPGP::Verify::detached_signature(key, data, sig) < 1) {
			return false;
		}

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}

	return true;
}

bool OpenPGPManager::getFingerprint(const std::string& pubKey, std::string& outFingerprint, std::string& outErrMsg) const {
	try {
                OpenPGP::PublicKey key(pubKey);
                if (!key.meaningful()) {
                        return false;
                }
		outFingerprint = hexlify(key.fingerprint());

	} catch (const std::exception& e) {
		outErrMsg = e.what();
		return false;
	}
	return true;
}
