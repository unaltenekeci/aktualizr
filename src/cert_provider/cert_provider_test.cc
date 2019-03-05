#include <gtest/gtest.h>

#include <boost/asio/io_service.hpp>
#include <boost/format.hpp>
#include <boost/process.hpp>

#include "config/config.h"
#include "utilities/utils.h"

static const char* CERT_PROVIDER_PATH = nullptr;
static const char* CREDENTIALS_PATH = nullptr;

class Process {
 public:
  using Result = std::tuple<int, std::string, std::string>;

  static Result spawn(const std::string& executable_to_run, const std::vector<std::string>& executable_args) {
    std::future<std::string> output;
    std::future<std::string> err_output;
    boost::asio::io_service io_service;

    int child_process_exit_code = -1;

    try {
      boost::process::child child_process(boost::process::exe = executable_to_run,
                                          boost::process::args = executable_args, boost::process::std_out > output,
                                          boost::process::std_err > err_output, io_service);

      io_service.run();

      child_process.wait_for(std::chrono::seconds(20));
      child_process_exit_code = child_process.exit_code();
    } catch (const std::exception& exc) {
      throw std::runtime_error("Failed to spawn process " + executable_to_run + " exited with an error: " + exc.what());
    }

    return std::make_tuple(child_process_exit_code, output.get(), err_output.get());
  }

  Process(const char* exe_path) : exe_path_(exe_path) {}

  Process::Result run(const std::vector<std::string>& args) {
    last_exit_code_ = -1;
    last_stdout_.clear();
    last_stderr_.clear();

    auto cred_gen_result = Process::spawn(exe_path_, args);
    std::tie(last_exit_code_, last_stdout_, last_stderr_) = cred_gen_result;

    return cred_gen_result;
  }

  int lastExitCode() const { return last_exit_code_; }

  const std::string& lastStdOut() const { return last_stdout_; }

  const std::string& lastStdErr() const { return last_stderr_; }

 private:
  const char* const exe_path_;

  int last_exit_code_;
  std::string last_stdout_;
  std::string last_stderr_;
};

class DeviceCredGenerator : public Process {
 public:
  DeviceCredGenerator(const char* exe_path) : Process(exe_path) {}

  class ArgSet {
   private:
    class Param {
     public:
      Param(const std::string& key, ArgSet* arg_set) : key_(key), arg_set_(arg_set) {}
      Param& operator=(const std::string& val) {
        arg_set_->arg_map_[key_] = val;
        return *this;
      }

      void clear() { arg_set_->arg_map_.erase(key_); }

     private:
      const std::string key_;
      ArgSet* arg_set_;
    };

    class Option {
     public:
      Option(const std::string& key, ArgSet* arg_set) : key_(key), arg_set_(arg_set) {}
      void set() { arg_set_->arg_set_.insert(key_); }
      void clear() { arg_set_->arg_set_.erase(key_); }

     private:
      const std::string key_;
      ArgSet* arg_set_;
    };

   public:
    Param fleetCA{"--fleet-ca", this};
    Param fleetCAKey{"--fleet-ca-key", this};
    Param localDir{"--local", this};
    Param directoryPrefix{"--directory", this};
    Param configFile{"--config", this};
    Param validityDays{"--days", this};
    Param countryCode{"--certificate-c", this};
    Param state{"--certificate-st", this};
    Param organization{"--certificate-o", this};
    Param commonName{"--certificate-cn", this};
    Param rsaBits{"--bits", this};
    Param credentialFile{"--credentials", this};

    Option provideRootCA{"--root-ca", this};
    Option provideServerURL{"--server-url", this};

   public:
    operator std::vector<std::string>() const {
      std::vector<std::string> res_vect;

      for (auto val_pair : arg_map_) {
        res_vect.push_back(val_pair.first);
        res_vect.push_back(val_pair.second);
      }

      for (auto key : arg_set_) {
        res_vect.push_back(key);
      }

      return res_vect;
    }

   private:
    std::unordered_map<std::string, std::string> arg_map_;
    std::set<std::string> arg_set_;
  };

  struct OutputPath {
    OutputPath(const std::string& root_dir, const std::string& prefix = "/var/sota/import",
               const std::string& private_key_file = "pkey.pem", const std::string& cert_file = "client.pem")
        : directory{prefix},
          privateKeyFile{private_key_file},
          certFile{cert_file},
          serverRootCA{"root.crt"},
          gtwURLFile{"gateway.url"},
          rootDir{root_dir},
          privateKeyFileFullPath{(rootDir / directory / privateKeyFile)},
          certFileFullPath{rootDir / directory / certFile},
          serverRootCAFullPath{rootDir / directory / serverRootCA},
          gtwURLFileFullPath{rootDir / gtwURLFile} {}

    const std::string directory;
    const std::string privateKeyFile;
    const std::string certFile;
    const std::string serverRootCA;
    const std::string gtwURLFile;

    const boost::filesystem::path rootDir;
    const boost::filesystem::path privateKeyFileFullPath;
    const boost::filesystem::path certFileFullPath;
    const boost::filesystem::path serverRootCAFullPath;
    const boost::filesystem::path gtwURLFileFullPath;
  };
};

class AktualizrCertProviderTest : public ::testing::Test {
 protected:
  struct TestArgs {
    TestArgs(const TemporaryDirectory& tmp_dir, const char* cred_path)
        : test_dir{tmp_dir.PathString()}, credentials_path(cred_path) {}

    const std::string test_dir;
    const std::string fleet_ca_cert = "tests/test_data/CAcert.pem";
    const std::string fleet_ca_private_key = "tests/test_data/CApkey.pem";
    const char* const credentials_path;
  };

 protected:
  TemporaryDirectory tmp_dir_;
  TestArgs test_args_{tmp_dir_, CREDENTIALS_PATH};
  DeviceCredGenerator device_cred_gen_{CERT_PROVIDER_PATH};
};

/**
 *  Verifies generation and serialization of a device private key and a certificate (including its signing)
 *  in case of the fleet credentials usage (i.e. a fleet private key) for the certificate signing.
 *
 *  - [x] Use fleet credentials if provided
 *  - [x] Read fleet CA certificate
 *  - [x] Read fleet private key
 *  - [x] Create device certificate
 *  - [x] Create device keys
 *  - [x] Set public key for the device certificate
 *  - [x] Sign device certificate with fleet private key
 *  - [x] Serialize device private key to a string (we actually can verify only 'searilized' version of the key )
 *  - [x] Serialize device certificate to a string (we actually can verify only 'serialized' version of the certificate)
 *  - [x] Write credentials to a local directory if requested
 *      - [x] Provide device private key
 *      - [x] Provide device certificate
 */

TEST_F(AktualizrCertProviderTest, DeviceCredCreationWithFleetCred) {
  DeviceCredGenerator::ArgSet args;

  args.fleetCA = test_args_.fleet_ca_cert;
  args.fleetCAKey = test_args_.fleet_ca_private_key;
  args.localDir = test_args_.test_dir;

  device_cred_gen_.run(args);
  ASSERT_EQ(device_cred_gen_.lastExitCode(), 0) << device_cred_gen_.lastStdErr();

  DeviceCredGenerator::OutputPath device_cred_path(test_args_.test_dir);

  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.privateKeyFileFullPath))
      << device_cred_path.privateKeyFileFullPath;
  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.certFileFullPath)) << device_cred_path.certFileFullPath;

  Process openssl("/usr/bin/openssl");

  openssl.run({"rsa", "-in", device_cred_path.privateKeyFileFullPath.string(), "-noout", "-check"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_EQ(openssl.lastStdOut(), "RSA key ok\n") << openssl.lastStdOut();

  openssl.run({"x509", "-in", device_cred_path.certFileFullPath.string(), "-noout", "-pubkey"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_NE(openssl.lastStdOut().find("-----BEGIN PUBLIC KEY-----\n"), std::string::npos) << openssl.lastStdOut();

  openssl.run({"rsa", "-in", device_cred_path.privateKeyFileFullPath.string(), "-noout", "-modulus"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  const std::string private_key_modulus = openssl.lastStdOut();

  openssl.run({"x509", "-in", device_cred_path.certFileFullPath.string(), "-noout", "-modulus"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  const std::string public_key_modulus = openssl.lastStdOut();

  ASSERT_EQ(private_key_modulus, public_key_modulus);

  openssl.run({"verify", "-verbose", "-CAfile", test_args_.fleet_ca_cert, device_cred_path.certFileFullPath.string()});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_EQ(openssl.lastStdOut(), str(boost::format("%1%: OK\n") % device_cred_path.certFileFullPath.string()));
}

/**
 * Verifies cert_provider's output if an incomplete set of fleet credentials is specified.
 * Just  a fleet CA without a fleet private key.
 * Just a fleet private key without a fleet CA
 * Neither `--target` nor `--local` is specified
 *
 * Checks actions:
 *
 *  - [x] Abort if fleet CA is provided without fleet private key
 *  - [x] Abort if fleet private key is provided without fleet CA
 */

TEST_F(AktualizrCertProviderTest, IncompleteFleetCredentials) {
  const std::string expected_error_msg = "fleet-ca and fleet-ca-key options should be used together\n";

  {
    DeviceCredGenerator::ArgSet args;

    args.fleetCA = test_args_.fleet_ca_cert;
    // args.fleetCAKey = test_args_.fleet_ca_private_key;
    args.localDir = test_args_.test_dir;

    device_cred_gen_.run(args);

    ASSERT_EQ(device_cred_gen_.lastExitCode(), 1);
    ASSERT_EQ(device_cred_gen_.lastStdErr(), expected_error_msg) << device_cred_gen_.lastStdErr();
  }

  {
    DeviceCredGenerator::ArgSet args;

    // args.fleetCA = test_args_.fleet_ca_cert;
    args.fleetCAKey = test_args_.fleet_ca_private_key;
    args.localDir = test_args_.test_dir;

    device_cred_gen_.run(args);

    ASSERT_EQ(device_cred_gen_.lastExitCode(), 1);
    ASSERT_EQ(device_cred_gen_.lastStdErr(), expected_error_msg) << device_cred_gen_.lastStdErr();
  }

  {
    DeviceCredGenerator::ArgSet args;

    args.fleetCA = test_args_.fleet_ca_cert;
    args.fleetCAKey = test_args_.fleet_ca_private_key;
    // args.localDir = test_args_.test_dir;

    device_cred_gen_.run(args);

    ASSERT_EQ(device_cred_gen_.lastExitCode(), 1);
    ASSERT_NE(device_cred_gen_.lastStdErr().find("Both a local dir and a target are not specified,"
                                                 " thus the resultant cert and key will be lost"),
              std::string::npos)
        << device_cred_gen_.lastStdErr();
  }
}

/**
 * Verifies usage of the paths from a config file which is specified via `--config` param.
 * The resultant files's path, private key and certificate files, must correspond to what is specified in the config.
 *
 * Verifies cert_provider's output if both `--directory` and `--config` params are specified
 *
 * Checks actions:
 *
 *  - [x] Use file paths from config if provided
 */
TEST_F(AktualizrCertProviderTest, ConfigFilePathUsage) {
  const std::string base_path = "my_device_cred";
  const std::string private_key_file = "my_device_private_key.pem";
  const std::string cert_file = "my_device_cert.pem";

  Config config;
  config.import.base_path = base_path;
  config.import.tls_pkey_path = BasedPath(private_key_file);
  config.import.tls_clientcert_path = BasedPath(cert_file);

  auto test_conf_file = tmp_dir_ / "conf.toml";
  boost::filesystem::ofstream conf_file(test_conf_file);
  config.writeToStream(conf_file);
  conf_file.close();

  // for some reason the cert-provider uses the config's base path as suffix (the same as the 'directory' param) of the
  // local dir
  DeviceCredGenerator::OutputPath device_cred_path(test_args_.test_dir, base_path, private_key_file, cert_file);

  DeviceCredGenerator::ArgSet args;

  args.fleetCA = test_args_.fleet_ca_cert;
  args.fleetCAKey = test_args_.fleet_ca_private_key;
  args.localDir = test_args_.test_dir;
  args.configFile = test_conf_file.string();

  device_cred_gen_.run(args);

  ASSERT_EQ(device_cred_gen_.lastExitCode(), 0) << device_cred_gen_.lastStdErr();

  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.privateKeyFileFullPath))
      << "Private key file is missing: " << device_cred_path.privateKeyFileFullPath;
  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.certFileFullPath))
      << "Certificate file is missing: " << device_cred_path.certFileFullPath;

  {
    // The case when both 'directory' and 'config' parameters are specified
    args.directoryPrefix = "whatever-dir";

    device_cred_gen_.run(args);
    EXPECT_EQ(device_cred_gen_.lastExitCode(), 1) << device_cred_gen_.lastStdErr();
    EXPECT_EQ(device_cred_gen_.lastStdErr(),
              "Directory (--directory) and config (--config) options cannot be used together\n")
        << device_cred_gen_.lastStdErr();
  }
}

/**
 * Verifies application of the certificate's and key's parameters specified via parameters
 *
 * Checks actions:
 *
 * - [x] Specify device certificate expiration date
 * - [x] Specify device certificate country code
 * - [x] Specify device certificate state abbreviation
 * - [x] Specify device certificate organization name
 * - [x] Specify device certificate common name
 * - [x] Specify RSA bit length
 */

TEST_F(AktualizrCertProviderTest, DeviceCertParams) {
  const std::string validity_days = "100";
  auto expires_after_sec = (std::stoul(validity_days) * 24 * 3600) + 1;
  const std::string country_code = "UA";
  const std::string state = "Lviv";
  const std::string org = "ATS";
  const std::string common_name = "ats.org";
  const std::string rsa_bits = "1024";

  DeviceCredGenerator::ArgSet args;

  args.fleetCA = test_args_.fleet_ca_cert;
  args.fleetCAKey = test_args_.fleet_ca_private_key;
  args.localDir = test_args_.test_dir;

  args.validityDays = validity_days;
  args.countryCode = country_code;
  args.state = state;
  args.organization = org;
  args.commonName = common_name;
  args.rsaBits = rsa_bits;

  device_cred_gen_.run(args);
  ASSERT_EQ(device_cred_gen_.lastExitCode(), 0) << device_cred_gen_.lastStdErr();

  DeviceCredGenerator::OutputPath device_cred_path(test_args_.test_dir);

  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.privateKeyFileFullPath))
      << device_cred_path.privateKeyFileFullPath;
  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.certFileFullPath)) << device_cred_path.certFileFullPath;

  // check subject's params
  const std::string expected_subject_str =
      str(boost::format("Subject: C = %1%, ST = %2%, O = %3%, CN = %4%") % country_code % state % org % common_name);

  Process openssl("/usr/bin/openssl");
  openssl.run({"x509", "-in", device_cred_path.certFileFullPath.string(), "-text", "-noout"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_NE(openssl.lastStdOut().find(expected_subject_str), std::string::npos);

  // check RSA length
  const std::string expected_key_str = str(boost::format("Private-Key: (%1% bit)") % rsa_bits);

  openssl.run({"rsa", "-in", device_cred_path.privateKeyFileFullPath.string(), "-text", "-noout"});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_NE(openssl.lastStdOut().find(expected_key_str), std::string::npos);

  // check expiration date
  openssl.run({"x509", "-in", device_cred_path.certFileFullPath.string(), "-noout", "-checkend",
               std::to_string(expires_after_sec - 1024)});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdOut();
  ASSERT_NE(openssl.lastStdOut().find("Certificate will not expire"), std::string::npos);

  openssl.run({"x509", "-in", device_cred_path.certFileFullPath.string(), "-noout", "-checkend",
               std::to_string(expires_after_sec)});
  ASSERT_EQ(openssl.lastExitCode(), 1) << openssl.lastStdOut();
  ASSERT_NE(openssl.lastStdOut().find("Certificate will expire"), std::string::npos);

  // check signature
  openssl.run({"verify", "-verbose", "-CAfile", test_args_.fleet_ca_cert, device_cred_path.certFileFullPath.string()});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_EQ(openssl.lastStdOut(), str(boost::format("%1%: OK\n") % device_cred_path.certFileFullPath.string()));
}

/**
 * Verifies the cert provider work in case of autoprovisioning credentials usage,
 * if the fleet CA and private key are not specified
 *
 * Check actions
 *
 * - [x] Use autoprovisioning credentials if fleet CA and private key are not provided
 *  - [x] Read server root CA from p12
 *  - [x] Provide root CA if requested
 *  - [x] Provide server URL if requested
 */

TEST_F(AktualizrCertProviderTest, AutoprovisioningCredsUsage) {
  if (test_args_.credentials_path == nullptr) {
    // GTEST_SKIP() was introduced in recent gtest version;
    SUCCEED() << "A path to the credentials file hasn't been proided, so skip the test";
    return;
  }

  DeviceCredGenerator::ArgSet args;

  args.credentialFile = test_args_.credentials_path;
  args.localDir = test_args_.test_dir;
  args.provideRootCA.set();
  args.provideServerURL.set();

  device_cred_gen_.run(args);
  std::cout << device_cred_gen_.lastStdOut();
  ASSERT_EQ(device_cred_gen_.lastExitCode(), 0) << device_cred_gen_.lastStdErr();

  DeviceCredGenerator::OutputPath device_cred_path(test_args_.test_dir);

  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.privateKeyFileFullPath))
      << device_cred_path.privateKeyFileFullPath;
  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.certFileFullPath)) << device_cred_path.certFileFullPath;

  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.serverRootCAFullPath))
      << device_cred_path.serverRootCAFullPath;
  ASSERT_TRUE(boost::filesystem::exists(device_cred_path.gtwURLFileFullPath)) << device_cred_path.gtwURLFileFullPath;

  Process openssl("/usr/bin/openssl");

  openssl.run({"verify", "-verbose", "-CAfile", device_cred_path.serverRootCAFullPath.string(),
               device_cred_path.certFileFullPath.string()});
  ASSERT_EQ(openssl.lastExitCode(), 0) << openssl.lastStdErr();
  ASSERT_EQ(openssl.lastStdOut(), str(boost::format("%1%: OK\n") % device_cred_path.certFileFullPath.string()));
}

#ifndef __NO_MAIN__
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  if (argc < 2) {
    std::cerr << "A path to the cert_provider is not specified." << std::endl;
    return EXIT_FAILURE;
  }

  CERT_PROVIDER_PATH = argv[1];
  std::cout << "Path to the cert_provider executable: " << CERT_PROVIDER_PATH << std::endl;

  if (argc == 3) {
    CREDENTIALS_PATH = argv[2];
    std::cout << "Path to the autoprovisioning credentials: " << CREDENTIALS_PATH << std::endl;
  }

  int test_run_res = RUN_ALL_TESTS();

  return test_run_res;
}
#endif
