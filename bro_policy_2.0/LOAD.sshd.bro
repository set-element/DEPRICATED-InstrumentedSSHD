### ----- ## ----- ###
redef Communication::listen_port = 32755/tcp;

@load sshd_analyzer
@load sshd_sftp

@load sshd_core
@load sshd_const
@load sshd_policy
@load sshd_sftp3
#@load sshd_input_stream
@load sshd_input_stream-bc
redef SSHD_IN_STREAM::data_file = "/data/sshd_data";

@load user_core

const in_trouble =
        /ettercap/
        &redef;

const out_trouble =
        /execshell/
	&redef;

redef SSHD_POLICY::input_trouble += in_trouble;
redef SSHD_POLICY::output_trouble += out_trouble;

redef SSHD_ANALYZER::input_trouble += in_trouble;
redef SSHD_ANALYZER::output_trouble += out_trouble;
