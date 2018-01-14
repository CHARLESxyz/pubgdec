3.6.4.8
 
decinit();
 
uworld = decptr(base_addr + 0x4054650);

game_instance = rpm64(uworld + 0x140);

...

gnames = decptr(base_addr + 0x3F36940);
 
for (index = 0; index < actor_count; ++index) {

	actor = decptr(actor_list + (index * 0x180));
	
}
