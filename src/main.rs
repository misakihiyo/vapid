use std::env;
use pelite::FileMap;
use pelite::pe32::{Pe, PeFile};
use regex::Regex;

fn main() {
    let exit_code = real_main();
    std::process::exit(exit_code); //exits the program with exitcode 1 if error and 0 if successful
}

fn real_main() -> i32 {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3{
        println!("The number of input values are invalid"); 
       return 1; //returns
    }

    let filename = &args[1]; // name of file
    let target_virtual_address_string = &args[2]; // target virtual address
   
    let file_map = FileMap::open(filename).unwrap();

    find_section(file_map.as_ref(),target_virtual_address_string).unwrap();

    return 0;
}

fn convert_to_numeric(value:&String) -> u32{
    // check if the input value is hexadecimal or decimal
    let re = Regex::new(r"^\b(0x[0-9a-fA-F]+|[0-9]+)\b$").unwrap(); 
    if re.is_match(value){
        //checking if argument is demical and convert
        if value.chars().all(char::is_numeric){
            let z:u32 = value.parse().unwrap();
            return z;
        }
        
        //convert hex value
        let no_prefix = value.trim_start_matches("0x");
        let hex_value = u32::from_str_radix(no_prefix, 16).unwrap();
        return hex_value;
    }

    println!("The virtual address provided is invalid");
    std::process::exit(1); //exit if the argument is invalid
}


fn find_section(image: &[u8], target_va:&String) -> pelite::Result<()> {
	// Interpret the bytes as a PE32+ executable
	let file = PeFile::from_bytes(image)?;

    //convert the argument from string into numeric value if valid
    let target_virtual_address = convert_to_numeric(target_va);

    let optional_header = file.optional_header();
    let image_base = optional_header.ImageBase;
    
    let section_headers = file.section_headers();
    
    //looping thorugh sections
    for x in section_headers { 
        let relative_virtual_address = x.VirtualAddress;
        let absolute_virtual_address = relative_virtual_address + image_base;
        
        //check if the target VA exists within the section
        if target_virtual_address < x.VirtualSize + absolute_virtual_address && target_virtual_address > absolute_virtual_address{
            let offset = target_virtual_address - absolute_virtual_address;
            let target_file_pointer = offset + x.PointerToRawData;
            println!("{:#06x} -> {:#06x}",target_virtual_address, target_file_pointer);
            return Ok(());
        }
        
    }

    println!("{:#06x} -> ??",target_virtual_address);
    Ok(())
}
