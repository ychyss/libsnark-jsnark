#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_h_se_ppzksnark/r1cs_h_se_ppzksnark.hpp>

#include <libff/algebra/field_utils/bigint.hpp>

#include <vector>
#include <string>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <sys/stat.h>
#include <sys/types.h>

using namespace libsnark;


template<typename ppT>
int run_r1cs_h_se_ppzksnark_setup(size_t num_constraints, size_t input_size, std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 保存pk和vk到文件
    std::string pkFileName = outputDir + "/pk";
    std::string vkFileName = outputDir + "/vk";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream pkFile(pkFileName, std::ios::binary);
    if (!pkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream vkFile(vkFileName, std::ios::binary);
    if (!vkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    
    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    logFile << "================================================================================\n";
    logFile << "ALgorithm: R1CS H SE GG-ppzkSNARK Generator\n";
    logFile << "================================================================================\n";

    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_keypair<ppT> keypair = r1cs_h_se_ppzksnark_generator<ppT>(example.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    printf("pk.alpha_g1=\n"); keypair.pk.alpha_g1.print();
    printf("pk.beta_g1=\n"); keypair.pk.beta_g1.print();
    printf("pk.beta_g2=\n"); keypair.pk.beta_g2.print();
    printf("pk.delta_g1=\n"); keypair.pk.delta_g1.print();
    printf("pk.delta_g2=\n"); keypair.pk.delta_g2.print();

    printf("vk.alpha_g1_beta_g2=\n"); keypair.vk.alpha_g1_beta_g2.print();
    printf("vk.gamma_g2=\n"); keypair.vk.gamma_g2.print();
    printf("vk.delta_g1=\n"); keypair.vk.delta_g1.print();
    printf("vk.delta_g2=\n"); keypair.vk.delta_g2.print();
    pkFile << keypair.pk;
    pkFile.flush();
    pkFile.close();
    vkFile << keypair.vk;
    vkFile.flush();
    vkFile.close();

    logFile.flush();
    logFile.close();

    return 0;
}


template<typename ppT>
int run_r1cs_h_se_ppzksnark_prove(size_t num_constraints, size_t input_size,std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 
    std::string pkFileName = outputDir + "/pk";
    std::string proofFileName = outputDir + "/proof";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream pkFile(pkFileName, std::ios::binary);
    if (!pkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream proofFile(proofFileName, std::ios::binary);
    if (!proofFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }

    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // 读取pk
    r1cs_h_se_ppzksnark_proving_key<ppT> pk;
    pkFile >> pk;

    printf("pk.alpha_g1=\n"); pk.alpha_g1.print();
    printf("pk.beta_g1=\n"); pk.beta_g1.print();
    printf("pk.beta_g2=\n"); pk.beta_g2.print();
    printf("pk.delta_g1=\n"); pk.delta_g1.print();
    printf("pk.delta_g2=\n"); pk.delta_g2.print();

    // 生成证明
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_proof<ppT> proof = r1cs_h_se_ppzksnark_prover<ppT>(pk, example.primary_input, example.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Prove Time: " << elapsed.count() << "s" << std::endl;

    printf("proof.A:\n"); proof.g_A.print();
    printf("proof.B:\n"); proof.g_B.print();
    printf("proof.C:\n"); proof.g_C.print();
    proofFile << proof;
    proofFile.flush();
    proofFile.close();

    return 0;

}

template<typename ppT>
int run_r1cs_h_se_ppzksnark_verify(size_t num_constraints, size_t input_size,std::string outputDir)
{
    // 日志
    std::string logFileName = outputDir + "/log.txt";
    // 
    std::string vkFileName = outputDir + "/vk";
    std::string proofFileName = outputDir + "/proof";

    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream vkFile(vkFileName, std::ios::binary);
    if (!vkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ifstream proofFile(proofFileName, std::ios::binary);
    if (!proofFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }

    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    
    // 读取vk和proof
    r1cs_h_se_ppzksnark_verification_key<ppT> vk;
    r1cs_h_se_ppzksnark_proof<ppT> proof;
    vkFile >> vk; 
    proofFile >> proof;

    printf("vk.alpha_g1_beta_g2=\n"); vk.alpha_g1_beta_g2.print();
    printf("vk.gamma_g2=\n"); vk.gamma_g2.print();
    printf("vk.delta_g1=\n"); vk.delta_g1.print();
    printf("vk.delta_g2=\n"); vk.delta_g2.print();

    printf("proof.A:\n"); proof.g_A.print();
    printf("proof.B:\n"); proof.g_B.print();
    printf("proof.C:\n"); proof.g_C.print();

    // 验证
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_h_se_ppzksnark_verifier_strong_IC<ppT>(vk, example.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    logFile << "The verification result is: " << (ans ? "PASS" : "FAIL") << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Verify Time: " << elapsed.count() << "s" << std::endl;

    return ans ? 0 : 2; // 2 代表未通过
}

template<typename ppT>
bool run_r1cs_h_se_ppzksnark(size_t num_constraints, size_t input_size, std::string outputDir)
{

    std::string logFileName = outputDir + "/log.txt";
    std::string pkFileName = outputDir + "/pk";
    std::string vkFileName = outputDir + "/vk";
    std::string proofFileName = outputDir + "/proof";
    std::ofstream logFile(logFileName, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream pkFile(pkFileName, std::ios::app);
    if (!pkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream vkFile(vkFileName, std::ios::app);
    if (!vkFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }
    std::ofstream proofFile(proofFileName, std::ios::app);
    if (!proofFile.is_open()) {
        std::cerr << "Unable to open file for writing." << std::endl;
        return 1;
    }

    logFile << "\n================================================================================\n";
    logFile << "Constraints Num:"<< num_constraints << std::endl;
    logFile << "Input Size:"<< input_size << std::endl;
    // 这个是生成r1cs约束的例子，不设计电路就用这个
    r1cs_example<libff::Fr<ppT> > example1 = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    auto start = std::chrono::high_resolution_clock::now();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    logFile << "================================================================================\n";
    logFile << "ALgorithm: R1CS H SE GG-ppzkSNARK Generator\n";
    logFile << "================================================================================\n";
    // 密钥对
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_keypair<ppT> keypair = r1cs_h_se_ppzksnark_generator<ppT>(example1.constraint_system);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile << "Gen Key Time: " << elapsed.count() << "s" << std::endl;
    // keypair.vk.delta_g1.print_coordinates();
    pkFile << keypair.pk;
    pkFile.close();
    vkFile << keypair.vk;
    vkFile.close();

    // 预处理vk
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_processed_verification_key<ppT> pvk = r1cs_h_se_ppzksnark_verifier_process_vk<ppT>(keypair.vk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Preprocess Time: " << elapsed.count() << "s" << std::endl;
    // 生成证明
    r1cs_example<libff::Fr<ppT> > example2 = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    start = std::chrono::high_resolution_clock::now();
    r1cs_h_se_ppzksnark_proof<ppT> proof = r1cs_h_se_ppzksnark_prover<ppT>(keypair.pk, example2.primary_input, example2.auxiliary_input);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Prove Time: " << elapsed.count() << "s" << std::endl;
    proofFile << proof;
    proofFile.close();
    // 验证
    r1cs_example<libff::Fr<ppT> > example3 = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    start = std::chrono::high_resolution_clock::now();
    const bool ans = r1cs_h_se_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example3.primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
    logFile << "The verification result is: " << (ans ? "PASS" : "FAIL") << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Verify Time: " << elapsed.count() << "s" << std::endl;
    // 
    start = std::chrono::high_resolution_clock::now();
    const bool ans2 = r1cs_h_se_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example3.primary_input, proof);
    assert(ans == ans2);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start; logFile<< "Online Verify Time: " << elapsed.count() << "s" << std::endl;

    logFile << "================================================================================\n\n";
    logFile.close();
    return ans;
}


template<typename ppT>
void test_r1cs_h_se_ppzksnark(size_t num_constraints, size_t input_size, std::string outputDir)
{

    run_r1cs_h_se_ppzksnark<ppT>(num_constraints, input_size, outputDir);
}


bool createDirectoryIfNotExists(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        // 尝试创建目录
        return mkdir(path.c_str(), 0755) == 0; // 使用适当的权限
    } else if (info.st_mode & S_IFDIR) {
        return true; // 目录已存在
    }
    return false; // 路径存在，但不是一个目录
}

// int main(int argc, char* argv[]) {
//     // 设置默认值
//     int num_constraints = 10000;
//     int input_size = 100;

//     // 如果提供了额外的参数，则更新默认值
//     if (argc >= 2) {
//         num_constraints = std::atoi(argv[1]);

//     }
//     if (argc >= 3) {
//         input_size = std::atoi(argv[2]);
//     }

//     if (num_constraints <= 0 || input_size <= 0) {
//         std::cerr << "Number of constraints and input size must be positive integers." << std::endl;
//         return 1;
//     }
    
//     // 输出文件
//     std::string outputDir("./h-se");
//     createDirectoryIfNotExists(outputDir);

//     default_r1cs_gg_ppzksnark_pp::init_public_params();
//     test_r1cs_h_se_ppzksnark<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);


//     return 0;
// }

int main(int argc, char* argv[]) {

    std::string mode = argv[1];
    if (mode == "test") {
        // 输出文件
        std::string outputDir("./h-se");
        // createDirectoryIfNotExists(outputDir);
        int num_constraints = 10000;
        int input_size = 10;
        // default_r1cs_gg_ppzksnark_pp::init_public_params();
        // test_r1cs_h_se_ppzksnark<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
        
        run_r1cs_h_se_ppzksnark_setup<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
        run_r1cs_h_se_ppzksnark_prove<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
        run_r1cs_h_se_ppzksnark_verify<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
        return 0;
    }

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <setup|prove|verify> num_constraints input_size outputDir" << std::endl;
        return 1;
    }


    size_t num_constraints = std::stoul(argv[2]);
    size_t input_size = std::stoul(argv[3]);
    std::string outputDir = argv[4];

    if (num_constraints <= 0 || input_size <= 0) {
        std::cerr << "Number of constraints and input size must be positive integers." << std::endl;
        return 1;
    }

    // 确保输出目录存在
    if (!createDirectoryIfNotExists(outputDir)) {
        std::cerr << "Failed to create or access output directory." << std::endl;
        return 1;
    }

    // 初始化公共参数
    default_r1cs_gg_ppzksnark_pp::init_public_params();

    // 根据模式调用相应的函数
    if (mode == "setup") {
        run_r1cs_h_se_ppzksnark_setup<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else if (mode == "prove") {
        run_r1cs_h_se_ppzksnark_prove<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else if (mode == "verify") {
        run_r1cs_h_se_ppzksnark_verify<default_r1cs_gg_ppzksnark_pp>(num_constraints, input_size, outputDir);
    } else {
        std::cerr << "Invalid mode. Use 'setup', 'prove', or 'verify'." << std::endl;
        return 1;
    }

    return 0;
}