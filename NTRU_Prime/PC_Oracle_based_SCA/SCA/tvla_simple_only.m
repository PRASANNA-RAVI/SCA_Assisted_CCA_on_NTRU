clear;

% Length of trace input here...
trace_length = 5000;
% No of traces in each trace set...
no_traces = 10;
% Trace start point for analysis...
trace_start_point = 1;

n=0;
n2=0;
X=zeros(1,trace_length);
Y=zeros(1,trace_length);
X2=zeros(1,trace_length);
Y2=zeros(1,trace_length);

first_no_traces_used_start = 1;
first_no_traces_used_end = no_traces;

second_no_traces_used_start = 1;
second_no_traces_used_end = no_traces;

%  Trace for c = 0...
first_file_name = 'traces_0';
ext='.mat';

%  Path containing traces for candidates for base ciphertext..

path = '/Users/pace/Dropbox/NTU/Programs/Lattice_programs/My_codes/NTRU_work/SCACCAONNTRU/NTRU_Prime/PC_Oracle_based_SCA/SCA/Pre-Processing_Phase/';


% We have traces captured for a total of 44 different ciphertexts...
% The 130th ciphertext is the base ciphertext...
% Testing TVLA between traces_0 and traces_x for x in
% [start_rep_file_count,rep_file_count]
% rep_file_count = 130 corresponds to base ciphertext whose TVLA is very
% high... For all others, TVLA has a very low value less than the pass/fail
% threshold...

start_rep_file_count = 1;
rep_file_count = 130;


fname=[path first_file_name ext];
disp(['Reading ' fname]);
load(fname);
traces=double(traces(first_no_traces_used_start:first_no_traces_used_end,trace_start_point:trace_length));

for row_no = 1:1:size(traces,1)
    traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
end

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

total_traces = length(start_rep_file_count:1:rep_file_count);
tvla_array_set = zeros(total_traces,trace_length);

for jg = start_rep_file_count:1:rep_file_count
 
    second_file_name = sprintf('traces_%d',jg);
    n = 0;
    fname=[path second_file_name ext];
    disp(['Reading ' fname]);
    load(fname);
    traces=double(traces(second_no_traces_used_start:second_no_traces_used_end,trace_start_point:trace_length));
    
    for row_no = 1:1:size(traces,1)
        traces(row_no, :) = traces(row_no, :) - mean(traces(row_no, :));
    end
    
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
    
    plot(tvla1(1:trace_length - trace_start_point+1))
    hold on
    plot([0,trace_length - trace_start_point+1],[4.5,4.5],'k')
    plot([0,trace_length - trace_start_point+1],[-4.5,-4.5],'k')
    xlabel('Time Samples')
    ylabel('TVLA Value')
    legend('TVLA-Set1-Set2','TVLA-PASS-FAIL-Threshold')
    tvla_array_set(jg,:) = tvla1;
end

