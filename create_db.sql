CREATE TABLE public.communications (
	MAC_src macaddr NOT NULL,
	MAC_dst macaddr NOT NULL,
	IP_src inet NOT NULL,
	IP_dst inet NOT NULL,
	is_tcp bool NOT NULL
);

-- Permissions

ALTER TABLE public.communications OWNER TO postgres;
GRANT ALL ON TABLE public.communications TO postgres;