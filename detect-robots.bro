##! Internet Robot detection.

@load base/frameworks/notice
@load base/protocols/http

module Robot;

export {
	# The fully resolved name dor this will be Robot::LOG
	redef enum Log::ID += { LOG };
        
        redef enum Notice::Type += {
            Robot_Detected
        }; 
        
	type Info: record {
          ts:    time    &log;
          uid:   string  &log;
	  id:          conn_id  &log;
          user_agent:   string   &log;
          uri:	string	&log;
        };

        #bot user_agents
        const robot_agents = /bot/ | /slurp/ | /robot/ | /scrap/ | /crawl/ | /spider/  &redef;
        
        global log_robot: event(rec: Info);
}

#Log that shit
event bro_init()
     {
     Log::create_stream(Robot::LOG, [$columns=Info, $ev=log_robot]);
     }
#catch our event and log it
event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=5
    {
    if ( name == "USER-AGENT" && robot_agents in value )
	{
        local log_info: Robot::Info = [$ts=network_time(), $uid=c$uid, $id=c$id, $user_agent=c$http$user_agent, $uri=c$http$uri, $ev=log_robot];
	Log::write(Robot::LOG, log_info);
        }
}
