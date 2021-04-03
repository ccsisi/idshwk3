global agent_table: table[addr] of set[string] = {};

event http_header(c: connection, is_orig: bool, name :string, value :string){
  local Addr :addr=c$id$orig_h;
  local UserAgent :string=to_lower(value);
  if(name=="USER-AGENT"){
    if(Addr in agent_table){
      add agent_table[Addr][UserAgent];
    }
    else{
      agent_table[Addr]=set(UserAgent);
    }
  }
}

event zeek_done(){
  local s :string=" is a proxy";
  for(i in agent_table){
    if((|agent_table[i]|)>=3)
      print i,s;
  }
}
