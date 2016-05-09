-module(xmpp_ofc_sids).
-behaviour(gen_server).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1,
         stop/1,
         handle_message/3]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% Includes & Type Definitions & Macros
%% ------------------------------------------------------------------

-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v4.hrl").
-include("xmpp_ofc_v4.hrl").

-record(state, {datapath_id :: binary(),
                clients}).

-define(SERVER, ?MODULE).
-define(OF_VER, 4).
-define(ENTRY_TIMEOUT, 30*1000).
-define(FM_TIMEOUT_S(Type), case Type of
                                idle ->
                                    10;
                                hard ->
                                    30
                            end).
-define(MAX_THRESHOLD, 100).
-define(FLOW_STAT_REQUEST_INTERVAL, 4 * 1000).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

-spec start_link(binary()) -> {ok, pid()} | ignore | {error, term()}.
start_link(DatapathId) ->
    {ok, Pid} = gen_server:start_link(?MODULE, [DatapathId], []),

    {ok, Pid, subscriptions(), [init_flow_mod()]}.

-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid).

-spec handle_message(pid(),
                     {MsgType :: term(),
                      Xid :: term(),
                      MsgBody :: [tuple()]},
                     [ofp_message()]) -> [ofp_message()].
handle_message(Pid, Msg, OFMessages) ->
    gen_server:call(Pid, {handle_message, Msg, OFMessages}).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init([DatapathId]) ->
    {ok, #state{datapath_id = DatapathId, clients = sets:new()}}.


handle_call({handle_message, {packet_in, _, MsgBody} = Msg, CurrOFMessages},
            _From, #state{datapath_id = Dpid, clients = Clients0} = State) ->
    case packet_in_extract(reason, MsgBody) of
        action ->
            {OFMessages, Clients1} = handle_packet_in(Msg, Dpid, Clients0),
            {reply, OFMessages ++ CurrOFMessages,
             State#state{clients = Clients1}};
        _ ->
            {reply, CurrOFMessages, State}
    end;

handle_call({handle_message, {flow_stats_reply, _, [{flags,[]},{flows,[]}]} = Msg, CurrOFMessages},
            _From, #state{datapath_id = Dpid} = State) ->
	{reply, [], State};

handle_call({handle_message, {flow_stats_reply, _, MsgBody} = Msg, CurrOFMessages},
            _From, #state{datapath_id = Dpid, clients = Clients0} = State) ->
    case flow_stats_extract(cookie, MsgBody) of 
        <<0,0,0,0,0,0,0,200>> ->
	     {OFMessages, Clients1} = handle_flow_stats_reply(Msg, Dpid, Clients0),
	    {reply,OFMessages ++ CurrOFMessages,State#state{clients = Clients1}};
	_ ->
	    {reply, CurrOFMessages , State}
end.

handle_cast(_Request, State) ->
    {noreply, State}.


handle_info({send_flow_stats_request, Dpid, TcpSrc, IpSrc}, State) ->
     ClientFlowModCookie = <<0,0,0,0,0,0,0,200>>,
     Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TcpSrc},
               {tcp_dst, <<5222:16>>}],
    TableId = 0,
    Cookie = ClientFlowModCookie,
    FlowStats = of_msg_lib:get_flow_statistics(?OF_VER,
                                               TableId,
                                               Matches,
                                               []),
    ofs_handler:send(Dpid, FlowStats),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.


code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

subscriptions() ->
    [packet_in, flow_stats_reply].

init_flow_mod() ->
    Matches = [{eth_type,16#0800}, {ip_proto, <<6>>}, {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, [{output, controller, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, 0},
                {idle_timeout, 0},
                {cookie, <<0,0,0,0,0,0,0,150>>},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).


handle_packet_in({_, Xid, PacketIn}, DatapathId, Clients0) ->
    [IpSrc, TCPSrc] = packet_in_extract([ipv4_src, tcp_src], PacketIn),
    Matches = [{eth_type, 16#0800},
		{ipv4_src, IpSrc},
		{ip_proto, <<6>>},
		{tcp_src, TCPSrc},
		{tcp_dst, <<5222:16>>}], 
    Instructions = [{apply_actions, [{output, 1, no_buffer}]}],
    FlowOpts = [{table_id, 0}, {priority, 150},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0,0,0,0,0,0,0,200>>},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],

    Clients1 =
    case sets:is_element({IpSrc,TCPSrc}, Clients0) or (TCPSrc == <<5222:16>>) of
        true  ->
            Clients0;
        false ->
            lager:info("New client, IP: ~p, TCPPort: ~p",[IpSrc,tcp_to_list(TCPSrc)]),
            schedule_flow_stats_request(DatapathId, TCPSrc, IpSrc),
            sets:add_element({IpSrc,TCPSrc},Clients0)
    end,

    FM = of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts),
    PO = packet_out(Xid, PacketIn, 1),
    {[FM, PO], Clients1}.


drop_flow_mod(IpSrc, TCPSrc) ->
    Matches = [{eth_type, 16#0800},
               {ipv4_src, IpSrc},
               {ip_proto, <<6>>},
               {tcp_src, TCPSrc},
               {tcp_dst, <<5222:16>>}],
    Instructions = [{apply_actions, []}],
    FlowOpts = [{table_id, 0}, {priority, 151},
                {idle_timeout, ?FM_TIMEOUT_S(idle)},
                {hard_timeout, ?FM_TIMEOUT_S(hard)},
                {cookie, <<0,0,0,0,0,0,0,200>>},
                {cookie_mask, <<0,0,0,0,0,0,0,0>>}],
    of_msg_lib:flow_add(?OF_VER, Matches, Instructions, FlowOpts).


handle_flow_stats_reply({_, _Xid, FlowStatsReply}, DatapathId, Clients0) ->
    [IpSrc, TCPSrc, PacketCount, DurationSec] =
        flow_stats_extract([ipv4_src,
                            tcp_src,
                            packet_count,
                            duration_sec], FlowStatsReply),

    lager:info("Client:, IP: ~p, TCPPort: ~p, packets: ~p",[IpSrc,tcp_to_list(TCPSrc),PacketCount]),
    schedule_flow_stats_request(DatapathId, TCPSrc, IpSrc),
    case packets_threshold_exceed(PacketCount, DurationSec) of
        true ->
            FM = drop_flow_mod(IpSrc, TCPSrc),
            {[FM], Clients0};
        false ->
            {[], Clients0}
    end.

schedule_flow_stats_request(Dpid, TCPSrc, IpSrc) ->
    timer:send_after(?FLOW_STAT_REQUEST_INTERVAL,
                     {send_flow_stats_request,
                      Dpid, TCPSrc, IpSrc}).


%%%%%%%%
%%%%%%%%
packets_threshold_exceed(PacketsCount, 0) ->
	false;
packets_threshold_exceed(PacketsCount, DurationMin) ->
	PacketsCount/(DurationMin/60) > ?MAX_THRESHOLD.

flow_stats_extract(AttrList,FlowStats) when is_list(AttrList) ->
	[flow_stats_extract(H,FlowStats) || H <- AttrList];

flow_stats_extract(flows, PacketIn) ->
    hd(proplists:get_value(flows, PacketIn));

flow_stats_extract(match, PacketIn) ->
    proplists:get_value(match, flow_stats_extract(flows, PacketIn));

flow_stats_extract(cookie, PacketIn) ->
    proplists:get_value(cookie, flow_stats_extract(flows,PacketIn));

flow_stats_extract(ipv4_src,PacketIn) ->
    proplists:get_value(ipv4_src,flow_stats_extract(match, PacketIn));

flow_stats_extract(tcp_src,PacketIn) ->
    proplists:get_value(tcp_src,flow_stats_extract(match,PacketIn));

flow_stats_extract(packet_count,PacketIn) ->
    proplists:get_value(packet_count, flow_stats_extract(flows, PacketIn));

flow_stats_extract(duration_sec,PacketIn) ->
    proplists:get_value(duration_sec, flow_stats_extract(flows, PacketIn)).


%%%%%%%%
%%%%%%%%%

packet_out(Xid, PacketIn, OutPort) ->
    Actions = [{output, OutPort, no_buffer}],
    {InPort, BufferIdOrPacketPortion} =
        case packet_in_extract(buffer_id, PacketIn) of
            no_buffer ->
                list_to_tuple(packet_in_extract([in_port, data],
                                                PacketIn));
            BufferId when is_integer(BufferId) ->
                {packet_in_extract(in_port, PacketIn), BufferId}
        end,
    PacketOut =  of_msg_lib:send_packet(?OF_VER,
                                        BufferIdOrPacketPortion,
                                        InPort,
                                        Actions),
    PacketOut#ofp_message{xid = Xid}.

packet_in_extract(Elements, PacketIn) when is_list(Elements) ->
    [packet_in_extract(H, PacketIn) || H <- Elements];
packet_in_extract(src_mac, PacketIn) ->
    <<_:6/bytes, SrcMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    SrcMac;
packet_in_extract(dst_mac, PacketIn) ->
    <<DstMac:6/bytes, _/binary>> = proplists:get_value(data, PacketIn),
    DstMac;
packet_in_extract(in_port, PacketIn) ->
    <<InPort:32>> = proplists:get_value(in_port, proplists:get_value(match, PacketIn)),
    InPort;

packet_in_extract(buffer_id, PacketIn) ->
    proplists:get_value(buffer_id, PacketIn);
packet_in_extract(data, PacketIn) ->
    proplists:get_value(data, PacketIn);
packet_in_extract(reason, PacketIn) ->
    proplists:get_value(reason, PacketIn);
packet_in_extract(ipv4_src, PacketIn) ->
	EthData = proplists:get_value(data, PacketIn),
	<<_:26/bytes, IpSrc:4/bytes, _/binary>> = EthData,
	IpSrc;
packet_in_extract(tcp_src, PacketIn) ->
	EthData = proplists:get_value(data, PacketIn),

	<<_:14/bytes, _ipv:4, IHL:4, IPData/binary>> = EthData,

        OptionsLen = case IHL of
		N when N > 5 -> 19;
		_ -> 19
	end,
	<< _Opts:OptionsLen/bytes, TcpSrc:2/bytes,_/binary>> = IPData,
	TcpSrc.

format_mac(MacBin) ->
    Mac0 = [":" ++ integer_to_list(X, 16) || <<X>> <= MacBin],
    tl(lists:flatten(Mac0)).

tcp_to_list(TCP) ->
    <<Tmp:16>> = TCP,
    integer_to_list(Tmp).
