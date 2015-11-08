% trivial OTP based DNS proxy
% no caching no logging no shugar
% just transparent DNS proxy

-module(tdns).
-behaviour(supervisor).

-record(tdns_option, {
  option       = [binary],
  port         = 53,
  max_restarts = 3000,
  time         = 60,
  shutdown     = 2000,
  recv_length  = 0,
  recv_timeout = 2000
}).
 

-compile(export_all). 

-define(T(),io:format("~p:~p ~n",[?MODULE,?LINE])).
-define(TIMEOUT,1000).
-define(SERVERS, [{{77,88,8,3},53}]).
 
% Behaviour Callbacks

behaviour_info(callbacks) -> [{handle_call, 4}, {handle_info, 2}];
behaviour_info(_Other) -> undefined.
 
% Supervisor
%% External APIs

start_link(Module) -> 
 ?T(),
 start_link(Module, #tdns_option{}).
 
start_link(RegistName, Module) when is_atom(Module) ->
 ?T(),
  start_link(RegistName, Module, #tdns_option{});

start_link(Module, Option) ->
 ?T(),
  start_link({local, ?MODULE}, Module, Option).
 
start_link({Dest, Name}=RegistName, Module, Option) ->
  ?T(),
  supervisor:start_link(
    {Dest, supervisor_name(Name)},
    ?MODULE,
    [RegistName, Module, Option]
  ).
 
stop() -> 
 ?T(),
 stop(?MODULE).
 
stop(Name) ->
   ?T(),
  case whereis(supervisor_name(Name)) of
    Pid when is_pid(Pid) ->
      exit(Pid, normal),
      ok;
    _ -> not_started
  end.
 
supervisor_name(Name) when is_atom(Name)-> 
    ?T(),
    list_to_atom(atom_to_list(Name) ++ "_sup").
 
%% Callbacks
init([{_Dest, Name}=RegistName, Module, Option]) ->
  ?T(),
  #tdns_option{
    max_restarts = MaxRestarts,
    time = Time,
    shutdown = Shutdown
  } = Option,
  {ok, {{one_for_one, MaxRestarts, Time}, [
    {
      Name,
      {?MODULE, receiver_start_link, [RegistName, Module, Option]},
      permanent,
      Shutdown,
      worker,
      []
    }
  ]}}.
 
% ProcLib - udp_server_receiver
%% External APIs

receiver_start_link({Dest, Name}, Module, Option) ->
  ?T(),
  {ok, Pid}
    = proc_lib:start_link(?MODULE, receiver_init, [self(), Module, Option]),
  case Dest of
    local -> register(Name, Pid);
    _Global -> global:register_name(Name, Pid)
  end,
  {ok, Pid}.
 
%% Callbacks
receiver_init(Parent, Module, Option) ->
  ?T(),
  case gen_udp:open(
    Option#tdns_option.port,
    Option#tdns_option.option
  ) of
    {ok, Socket} ->
      proc_lib:init_ack(Parent, {ok, self()}),
      recv(
        proplists:get_value(active, Option#tdns_option.option),
        Socket, Module, Option
      );
    {error, Reason} -> exit({error, Reason})
  end.
 
recv(false, Socket, Module, Option) ->
  ?T(),
  case gen_udp:recv(
    Socket,
    Option#tdns_option.recv_length,
    Option#tdns_option.recv_timeout
  ) of
    {ok, {Address, Port, Packet}} ->
      Module:handle_call(Socket, Address, Port, Packet),
      recv(false, Socket, Module, Option);
    {error, Reason} -> exit({error, Reason})
  end;
 
recv(_Active, Socket, Module, Option) ->
  ?T(),
  receive
    {udp, Socket, Address, Port, Packet} ->
      Module:handle_call(Socket, Address, Port, Packet),
      recv(true, Socket, Module, Option);
    OtherMessage ->
      Module:handle_info(Socket, OtherMessage),
      recv(true, Socket, Module, Option)
  after Option#tdns_option.recv_timeout ->
    exit({error, udp_timeout})
  end.

handle_call(Socket, ClientIP, Port, Packet)->
 ?T(),
 io:format("~p:~p ~p ~n",[?MODULE,?LINE,{now(),Socket, ClientIP, Port, inet_dns:decode(Packet)}]),
 handle_query_tu(Socket, ClientIP, Port,inet_dns:decode(Packet)).

start()->?MODULE:start_link(?MODULE).

%%%% non OTP section, working horses here %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_header_id({dns_header,ID,_,_,_,_,_,_,_,_}) -> ID;
get_header_id(<<ID:16,Bin/bitstring>>)->ID.

inject_id(ID,<<_:16,Bin/bitstring>>)->  <<ID:16,Bin/bitstring>>.

handle_query_tu(Socket, 
                ClientIP, 
                Port,
                {ok,{dns_rec,Header,[{dns_query,Name,Class,Type}],_,_,_
                    }
                }
               )
 ->

 io:format("~p:~p query ~p ~n",[?MODULE,?LINE,{Name,Class,Type,now()}]),
 io:format("~p:~p resolved ~p ~n",[?MODULE,?LINE,inet_res:resolve(Name,Type,Class)]),
% io:format("~p:~p nnslookup ~p ~n",[?MODULE,?LINE,inet_res:nnslookup(Name,Type,Class,?SERVERS,?TIMEOUT)]),

 {ok,R}=inet_res:resolve(Name,Type,Class),
 
 Rbin=inet_dns:encode(R),
 ID=get_header_id(Header), % or from Bbin for more fast

 R_out=inject_id(ID,Rbin),
  gen_udp:send(Socket,ClientIP,Port,R_out);
% gen_udp:close(Socket);

handle_query_tu(Socket, 
                ClientIP, 
                Port,
                Inp 
               )
 -> io:format("~p:~p unknown input ~p ~n",[?MODULE,?LINE,Inp]).
