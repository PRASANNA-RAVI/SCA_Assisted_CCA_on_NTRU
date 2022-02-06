clear;

% Streamlined NTRU Prime Decryption Failure Oracle Attack...

% % Input path of the traces here...

% % Folder containing Profiling Traces...
profile_path = './Pre-Processing_Phase/';
% % Folder containing Attack Traces...
attack_path = './Attack_Phase/';
% % Folder containing Correct Oracle Response... This we use to match with
% the side-channel's oracle response...
oracle_file_name = './Attack_Phase/oracle_response.mat';

% Length of trace input here...
% % Length of trace that we consider for analysis... Initial Point and
% Final Point...

trace_ini_point = 500;
trace_final_point = 4500;
% Actual length of trace...
trace_length = 5000;

% No of traces in each trace set...
no_traces = 10;
no_traces_used = 10;
threshold_value = 7;

% Input file names of the first trace set and second trace set...
% Trace for ciphertext c = 0...

first_file_name = 'traces_0';
% Trace for base ciphertext...
second_file_name = 'traces_321';
ext='.mat';


% Total number of attack traces... For each coefficient, we have 4
% ciphertext queries...
start_attack_files = 0;
end_attack_files = 3043;
% No of traces in each set of attack traces... But, we only use 1...
no_traces_in_file = 2;
% No of attack traces used in each set for attack... Single-trace
% classification..
no_attack_traces_used = 1;


% Main code starts here...the analysis part...


% Here, we compute TVLA to identify the distinguishing features between c =
% 0 and c = cbase...

n=0;
n2=0;
X=zeros(1,trace_length);
Y=zeros(1,trace_length);
X2=zeros(1,trace_length);
Y2=zeros(1,trace_length);


fname=[profile_path first_file_name ext];
disp(['Reading ' fname]);
load(fname);
traces=double(traces(1:no_traces_used,:));
X=sum(traces);
X2=sum(traces.^2);
n=n+size(traces,1);
clear traces scalars points;

m_X=X/n;
v_X=(X2-(X.^2/n))/(n-1);
v_Xn=v_X/n;

m_CKCP=m_X;
v_CKCP=abs(v_X);
v_CKCP_n=v_Xn;

n = 0;
fname=[profile_path second_file_name ext];
disp(['Reading ' fname]);
load(fname);
traces=double(traces(1:no_traces_used,:));
X=sum(traces);
X2=sum(traces.^2);
n=n+size(traces,1);
clear traces;

m_X=X/n;
v_X=(X2-(X.^2/n))/(n-1);
v_Xn=v_X/n;

m_CKRP=m_X;
v_CKRP=abs(v_X);
v_CKRP_n=v_Xn;

tvla1= (m_CKRP-m_CKCP)./sqrt(v_CKCP/n+v_CKRP/n);

plot(tvla1)
hold on
plot([0,trace_length],[4.5,4.5],'k')
plot([0,trace_length],[-4.5,-4.5],'k')
xlabel('Time Samples')
ylabel('TVLA Value')
legend('TVLA-Set1-Set2','TVLA-PASS-FAIL-Threshold')

% Based on tvla value, we choose an appropriate threshold and choose those points as points of interest
% that are above and below a certain threshold. We then construct a
% reduced trace and use the reduced trace to build a reduced template...

threshold = threshold_value;
leaky_points_no_negative = 0;
for i = trace_ini_point:1:trace_final_point
    if(abs(tvla1(i)) >= threshold)
        leaky_points_no_negative = leaky_points_no_negative+1;
    end
end
leaky_indices_negative = zeros(1,leaky_points_no_negative);

k = 1;
for i = trace_ini_point:1:trace_final_point
    if(abs(tvla1(i)) >= threshold)
        leaky_indices_negative(1,k) = i;
        k = k+1;
    end
end

% Now calculate mean of each trace in the set and get a reduced template
% trace...

mean_trace_correct = zeros(1,leaky_points_no_negative);
mean_trace_faulty = zeros(1,leaky_points_no_negative);

fname=[profile_path first_file_name ext];
load(fname);
correct_traces=double(traces);
for row_no = 1:1:size(traces,1)
    correct_traces(row_no, :) = correct_traces(row_no, :) - mean(correct_traces(row_no, :));
end

for i = 1:1:leaky_points_no_negative
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + correct_traces(j,leaky_indices_negative(i));
    end
    mean_trace_correct(i) = sum_points/no_traces_used;
end

% Taking mean of PoI in trace set 2 for all traces...

fname=[profile_path second_file_name ext];
load(fname);
faulty_traces=double(traces);
for row_no = 1:1:size(traces,1)
    faulty_traces(row_no, :) = faulty_traces(row_no, :) - mean(faulty_traces(row_no, :));
end

for i = 1:1:leaky_points_no_negative
    sum_points = 0;
    for j = 1:1:no_traces_used
        sum_points = sum_points + faulty_traces(j,leaky_indices_negative(i));
    end
    mean_trace_faulty(i) = sum_points/no_traces_used;
end

% Figure of clustering of the two clusters...

figure;
hold on;
plot(mean_trace_correct,'b');
plot(mean_trace_faulty,'r');

% Performing the actual attack (LSQ test based on reduced templates)...

reduced_trace = zeros(1,leaky_points_no_negative);

% Performing attack based on attack_threshold...

disp('Performing attack on poly 1 of secret...');

succ = 0;

selection_array = zeros(1,end_attack_files - start_attack_files + 1);

success = 0;
load(oracle_file_name);

for i = start_attack_files:1:end_attack_files

    fform = 'traces_';
    ext='.mat';
    trace_no = num2str(i);
    fname=[attack_path fform trace_no ext];
    load(fname);
    traces=double(traces);
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end

    current_trace = zeros(1,trace_length);

    for j = 1:1:no_attack_traces_used
        index_now = randi(no_traces_in_file);
        trace_nnow = traces(index_now,:);
        current_trace = current_trace + trace_nnow;
    end

    current_trace = current_trace/(no_attack_traces_used);

    index = 1;
    for oo = 1:1:leaky_points_no_negative
        reduced_trace(index) = current_trace(leaky_indices_negative(oo));
        index = index+1;
    end

    lsq_correct = ((mean_trace_correct - reduced_trace)*transpose(mean_trace_correct - reduced_trace));
    lsq_faulty = ((mean_trace_faulty - reduced_trace)*transpose(mean_trace_faulty - reduced_trace));

% % To visualize the reduced traces and the actual reduced attack trace...
%     figure;
%     hold on;
%     plot(mean_trace_correct,'b');
%     plot(mean_trace_faulty,'r');
%     plot(reduced_trace,'g');

    if(lsq_correct < lsq_faulty)
        selection_array(i - start_attack_files +1) = 0;
        disp("0")
    else
        selection_array(i - start_attack_files +1) = 1;
        disp("1")
    end

    if(selection_array(i - start_attack_files +1) == oracle_response_array(i + 1))
        success = success+1;
    end

    success_string = sprintf("Success: %d/%d",success,(end_attack_files+1));
    success_string
end
