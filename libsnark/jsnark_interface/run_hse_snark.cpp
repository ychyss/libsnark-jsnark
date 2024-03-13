/**
 * @file run_hse_snark.cpp
 * @author HYS
 * @brief
 * @version 0.1
 * @date 2024-03-12
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_h_se_ppzksnark/r1cs_h_se_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libff/algebra/fields/prime_base/fp.hpp>

template <typename T>
void WriteMemToFile(const T &obj, const std::string path)
{
  std::stringstream ss;
  ss << obj;
  std::ofstream fh;
  fh.open(path, std::ios::binary);
  ss.rdbuf()->pubseekpos(0, std::ios_base::out);
  fh << ss.rdbuf();
  fh.flush();
  fh.close();
}

template <typename T>
void loadFromFile(std::string path, T *p)
{
  std::stringstream ss;
  std::ifstream fh(path, std::ios::binary);

  assert(fh.is_open());

  ss << fh.rdbuf();
  fh.close();
  ss.rdbuf()->pubseekpos(0, std::ios_base::in);

  // vector<char> buf(fh.seekg(0, std::ios::end).tellg());
  // fh.seekg(0, std::ios::beg).read(&buf[0], static_cast<std::streamsize>(buf.size()));
  // fh.close();

  // ss << buf.begin();
  // ss.rdbuf()->pubseekpos(0, std::ios_base::in);

  // T obj;//(std::move(buf))
  ss >> *p;
  // obj = &buf[0];

  // return obj;
}

/**
 * @brief 读取证明密钥
 *
 * @param pk_path
 * @param pk
 */
template <typename T>
void deserializePKFromFile(const std::string &pk_path, T *pk)
{
  loadFromFile<T>(pk_path, pk);
  // return loadFromFile<r1cs_gg_ppzksnark_proving_key<libsnark::default_r1cs_gg_ppzksnark_pp>>(pk_path);
}

template <typename T>
void deserializeVKFromFile(const std::string &vk_path, T *vk)
{
  loadFromFile<T>(vk_path, vk);
  // return loadFromFile<r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp>>(vk_path);
}

template <typename T>
void serializeVKToFile(const T &vk, const std::string &vk_path)
{
  WriteMemToFile<T>(vk, vk_path);
}

// /**
//  * @brief setup
//  * 
//  * @tparam ppT 
//  * @param reader 
//  * @return int 
//  */
// template<typename ppT>
// int run_r1cs_h_se_ppzksnark_setup(const CircuitReader& reader)
// {
//   // Read the circuit, evaluate, and translate constraints
//   r1cs_constraint_system<ppT> cs = get_constraint_system_from_gadgetlib2(*reader.pb);
//   const r1cs_variable_assignment<ppT> full_assignment = get_variable_assignment_from_gadgetlib2(*reader.pb);
//   cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
//   cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

//   // extract primary and auxiliary input
//   r1cs_primary_input<ppT> primary_input(full_assignment.begin(),	full_assignment.begin() + cs.num_inputs());
//   r1cs_auxiliary_input<ppT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());

//   if(!cs.is_satisfied(primary_input, auxiliary_input))
//   {
//     cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
//     return -1;
//   }
//   r1cs_variable_assignment<FieldT>().swap(full_assignment);
//   r1cs_primary_input<FieldT>().swap(primary_input);
//   r1cs_auxiliary_input<FieldT>().swap(auxiliary_input);

//   libff::enter_block("Call to generator");
//   libff::print_header("R1CS H-SE-SNARK Generator");

//   r1cs_h_se_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_h_se_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(cs);
//   printf("\n"); 
//   libff::print_indent(); 
//   libff::print_mem("after generator");
//   libff::leave_block("Call to generator");

//   //////////////////////////////////////////////////////////////////////////////////////////////////////////
//   libff::enter_block("WriteMemToFile");
//   WriteMemToFile(keypair.pk, "mintpk.txt");
//   // WriteMemToFile(keypair.vk, "mintvk.txt");
//   serializevkToFile(keypair.vk, "mintvk.txt");
//   libff::leave_block("WriteMemToFile");

// }

r1cs_primary_input<FieldT> getPrimaryInput(char* arithFilepath, char* inputsFilepath)
{
	r1cs_primary_input<FieldT> primary_input;
	ifstream arithfs(arithFilepath, ifstream::in);
	ifstream inputfs(inputsFilepath, ifstream::in);
	string line;

	char* inputStr;

	std::vector<Wire> inputWireIds;
	unsigned int numInputs = 0;

	while (getline(arithfs, line)) {
		if (line.length() == 0) {
			continue;
		}
		inputStr = new char[line.size()];

		if ((line[0] != 'i') || (line[1] != 'n') || (line[2] != 'p') || (line[3] != 'u') || (line[4] != 't')) 
			continue;
		Wire wireId;
		sscanf(line.c_str(), "input %u", &wireId);
		numInputs++;
		inputWireIds.push_back(wireId);

		delete[] inputStr;
	}
	arithfs.close();

	
	while (getline(inputfs, line)) {
		if (line.length() == 0) {
			continue;
		}
		Wire wireId;
		inputStr = new char[line.size()];
		if (2 == sscanf(line.c_str(), "%u %s", &wireId, inputStr)) {
			for (int i = 0; i < inputWireIds.size(); ++i) {
				if (inputWireIds[i] == wireId) {
					primary_input.push_back(readFieldElementFromHex(inputStr));
					break;
				}
			}
		} else {
			printf("Error in Input\n");
			exit(-1);
		}
		delete[] inputStr;
	}
	inputfs.close();
	
	return primary_input;
}


int main(int argc, char **argv)
{
  if (argc != 4)
  {
    std::cerr << "Usage: " << argv[0] << " <setup|prove|verify> arithPath inputsPath" << std::endl;
    return 1;
  }

  // 参数解析
  std::string mode = argv[1];

  libff::start_profiling();
  if (mode == "setup")
  {
    std::string arithPath = argv[2];
    std::string inputsPath = argv[3];

    gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    // 通过电路和输入文件创建电路 Read the circuit, evaluate, and translate constraints
    CircuitReader reader(argv[2], argv[3], pb);
		r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
		r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();
		// extract primary and auxiliary input
		r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),	full_assignment.begin() + cs.num_inputs());
		r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
		if(!cs.is_satisfied(primary_input, auxiliary_input))
		{
			cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
			return -1;
		}
		// r1cs_variable_assignment<FieldT>().swap(full_assignment);
		// r1cs_primary_input<FieldT>().swap(primary_input);
		// r1cs_auxiliary_input<FieldT>().swap(auxiliary_input);

		libff::enter_block("Call to generator");
		libff::print_header("R1CS H-SE-ppzkSNARK Generator");
		r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);
		// r1cs_h_se_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair = r1cs_h_se_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);
		printf("\n"); 
		libff::print_indent(); 
		libff::print_mem("after generator");
		libff::leave_block("Call to generator");

		//////////////////////////////////////////////////////////////////////////////////////////////////////////
		libff::enter_block("WriteMemToFile");
		WriteMemToFile<r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp>>(keypair.pk, "mintpk.txt");
		// WriteMemToFile(keypair.vk, "mintvk.txt");
		serializeVKToFile<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>(keypair.vk, "mintvk.txt");
		libff::leave_block("WriteMemToFile");

    // int ret = run_r1cs_h_se_ppzksnark_setup<default_r1cs_gg_ppzksnark_pp>(reader);
    return 0;
  }
  else if (mode == "prove")
  {
    std::string arithPath = argv[2];
    std::string inputsPath = argv[3];

    gadgetlib2::initPublicParamsFromDefaultPp();
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

    CircuitReader reader(argv[2], argv[3], pb);
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
    r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

		r1cs_primary_input<FieldT> primary_input1(full_assignment.begin(),	full_assignment.begin() + cs.num_inputs());
		r1cs_auxiliary_input<FieldT> auxiliary_input1(full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair;
    // r1cs_h_se_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair;

		libff::enter_block("ReadMemFromFile mintpk.txt");
    deserializePKFromFile<r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp>>("mintpk.txt", &keypair.pk);
		libff::leave_block("ReadMemFromFile mintpk.txt");
		libff::print_mem("after ReadMemFromFile mintpk.txt");

		libff::enter_block("ReadMemFromFile mintvk.txt");
		deserializeVKFromFile<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>("mintvk.txt", &keypair.vk);
		libff::leave_block("ReadMemFromFile mintvk.txt");
		libff::print_mem("after ReadMemFromFile mintvk.txt");

    if(!keypair.pk.constraint_system.is_satisfied(primary_input1, auxiliary_input1))
		{
			cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
			return -1;
		}

    libff::enter_block("R1CS H-SE-ppzkSNARK Prover");
		libff::print_header("R1CS H-SE-ppzkSNARK Prover");
    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(keypair.pk, primary_input1, auxiliary_input1);
    // r1cs_h_se_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof = r1cs_h_se_ppzksnark_prover<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.pk, primary_input1, auxiliary_input1);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");
		libff::leave_block("R1CS H-SE-ppzkSNARK Prover");
		WriteMemToFile<r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp>>(proof, "proof");

		return 0;
  }
  else if (mode == "verify")
  {
    gadgetlib2::initPublicParamsFromDefaultPp();
		gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		
    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair;
		// r1cs_h_se_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair;
    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof;
		// r1cs_h_se_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof;

		r1cs_primary_input<FieldT> primary_input = getPrimaryInput(argv[2], argv[3]);

		libff::enter_block("Read mintvk");
		deserializeVKFromFile<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>("mintvk.txt", &keypair.vk);

		libff::print_mem("Read proof");	
		loadFromFile<r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp>>("proof", &proof);

		libff::leave_block("ReadMemFromFile");

		libff::print_header("R1CS H-SE-ppzkSNARK Verifier");
    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.vk, primary_input, proof);
		// const bool ans = r1cs_h_se_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.vk, primary_input, proof);
		printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
		printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));
		
		return 0;
  }else if(mode == "test") {
    // std::string arithPath = argv[2];
    // std::string inputsPath = argv[3];

    // gadgetlib2::initPublicParamsFromDefaultPp();
		// gadgetlib2::GadgetLibAdapter::resetVariableIndex();
		// ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    // // 通过电路和输入文件创建电路 Read the circuit, evaluate, and translate constraints
    // CircuitReader reader(argv[2], argv[3], pb);
		// r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
		// r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
		// cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
		// cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();
		// // extract primary and auxiliary input
		// r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),	full_assignment.begin() + cs.num_inputs());
		// r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());
		// if(!cs.is_satisfied(primary_input, auxiliary_input))
		// {
		// 	cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		// 	return -1;
		// }
		// // r1cs_variable_assignment<FieldT>().swap(full_assignment);
		// // r1cs_primary_input<FieldT>().swap(primary_input);
		// // r1cs_auxiliary_input<FieldT>().swap(auxiliary_input);

    // libff::enter_block("Call to generator");
		// libff::print_header("R1CS H-SE-ppzkSNARK Generator");
    // r1cs_h_se_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> keypair = r1cs_h_se_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(cs);
    // libff::leave_block("Call to generator");
    // libff::enter_block("R1CS H-SE-ppzkSNARK Prover");
		// libff::print_header("R1CS H-SE-ppzkSNARK Prover");
    // r1cs_h_se_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> proof = r1cs_h_se_ppzksnark_prover<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.pk, primary_input, auxiliary_input);
    // libff::leave_block("R1CS H-SE-ppzkSNARK Prover");
    // libff::print_header("R1CS H-SE-ppzkSNARK Verifier");
    // const bool ans = r1cs_h_se_ppzksnark_verifier_strong_IC<libsnark::default_r1cs_gg_ppzksnark_pp>(keypair.vk, primary_input, proof);
    // printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));


    return 0;
  }
}
