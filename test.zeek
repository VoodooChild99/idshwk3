global srcip_agent_table: table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if(is_orig && (to_lower(name) == "user-agent"))
	{
		if(c$id$orig_h in srcip_agent_table)
		{
			add srcip_agent_table[c$id$orig_h][to_lower(value)];
			if(|srcip_agent_table[c$id$orig_h]| >= 3)
			{
				print fmt("%s is a proxy", c$id$orig_h);
			}
		}
		else
		{
			srcip_agent_table[c$id$orig_h] = set(to_lower(value));
		}
	}
}
