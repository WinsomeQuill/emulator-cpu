// Регистры общего назначения x86 (32-битные)
#[derive(Debug, Clone, Copy)]
struct Registers {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    esi: u32,
    edi: u32,
    esp: u32,
    ebp: u32,
    eip: u32,    // Указатель инструкций
    eflags: u32, // Флаги
}

impl Registers {
    fn new() -> Self {
        Registers {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            esi: 0,
            edi: 0,
            esp: 0xFFFF_FFF0, // Инициализируем стек
            ebp: 0xFFFF_FFF0,
            eip: 0,
            eflags: 0,
        }
    }

    fn get(&self, reg: &str) -> u32 {
        match reg.to_lowercase().as_str() {
            "eax" => self.eax,
            "ebx" => self.ebx,
            "ecx" => self.ecx,
            "edx" => self.edx,
            "esi" => self.esi,
            "edi" => self.edi,
            "esp" => self.esp,
            "ebp" => self.ebp,
            "eip" => self.eip,
            _ => panic!("Unknown register: {}", reg),
        }
    }

    fn set(&mut self, reg: &str, value: u32) {
        match reg.to_lowercase().as_str() {
            "eax" => self.eax = value,
            "ebx" => self.ebx = value,
            "ecx" => self.ecx = value,
            "edx" => self.edx = value,
            "esi" => self.esi = value,
            "edi" => self.edi = value,
            "esp" => self.esp = value,
            "ebp" => self.ebp = value,
            "eip" => self.eip = value,
            _ => panic!("Unknown register: {}", reg),
        }
    }
}

#[derive(Debug, Clone)]
enum SectionRes {
    resb, // 1 byte
    resw, // 2 bytes (1 word)
    resd, // 4 bytes (2 word)
    resq, // 8 bytes (4 word)
}

#[derive(Debug, Clone)]
enum Section {
    Bss {
        name: String,
        res: SectionRes,
        size: u32,
        start_addr: u32,
    },
    Data {
        name: String,
        res: SectionRes,
        values: Vec<u8>,
        start_addr: u32,
    },
    Text {
        name: String,
        start_addr: u32,
    },
}

impl Section {
    fn name(&self) -> &str {
        match self {
            Section::Bss { name, .. } => name,
            Section::Data { name, .. } => name,
            Section::Text { name, .. } => name,
        }
    }

    fn start_addr(&self) -> u32 {
        match self {
            Section::Bss { start_addr, .. } => *start_addr,
            Section::Data { start_addr, .. } => *start_addr,
            Section::Text { start_addr, .. } => *start_addr,
        }
    }

    fn size(&self) -> u32 {
        match self {
            Section::Bss { size, .. } => *size,
            Section::Data { values, .. } => values.len() as u32,
            Section::Text { .. } => 0,
        }
    }
}

// Состояние процессора
struct CPU {
    regs: Registers,
    memory: Vec<u8>,
    running: bool,
    sections: Vec<Section>,
}

impl CPU {
    fn new(memory_size: usize) -> Self {
        CPU {
            regs: Registers::new(),
            memory: vec![0; memory_size],
            running: false,
            sections: vec![],
        }
    }

    fn allocate_memory_for_sections(&mut self) {
        let mut current_addr = 0;
        let mut data_to_write: Vec<(usize, Vec<u8>)> = Vec::new();

        for section in &mut self.sections {
            match section {
                Section::Bss {
                    start_addr, size, ..
                } => {
                    *start_addr = current_addr;
                    data_to_write.push((current_addr as usize, vec![0; *size as usize]));
                    current_addr += *size;
                }

                Section::Data {
                    start_addr, values, ..
                } => {
                    *start_addr = current_addr;
                    data_to_write.push((current_addr as usize, values.clone()));
                    current_addr += values.len() as u32;
                }

                Section::Text { start_addr, .. } => {
                    *start_addr = current_addr;
                    // TODO: Подумать как загружать text
                }
            }
        }

        for (addr, data) in data_to_write {
            self.write_memory(addr, &data);
        }
    }

    fn section(&mut self, section: &[&str]) {
        if section.len() < 2 {
            panic!("Invalid section");
        }

        match section[0] {
            ".bss" => {
                if section.len() != 4 {
                    panic!("Invalid .bss section syntax");
                }

                let res = match section[2] {
                    "resb" => SectionRes::resb,
                    "resw" => SectionRes::resw,
                    "resd" => SectionRes::resd,
                    "resq" => SectionRes::resq,
                    _ => panic!("Invalid reservation: {}", section[2]),
                };

                let size = section[3].parse::<u32>().unwrap();

                self.sections.push(Section::Bss {
                    name: section[1].to_string(),
                    res,
                    size,
                    start_addr: 0, // Будет установлено при аллокации
                });
            }

            ".data" => {
                // TODO: Сделать парсинг инициализированных данных
                //let values = parse_data_section(&section[2..]);

                self.sections.push(Section::Data {
                    name: section[1].to_string(),
                    res: SectionRes::resb, // По умолчанию, можно уточнять
                    values: vec![],
                    start_addr: 0,
                });
            }

            ".text" => {
                self.sections.push(Section::Text {
                    name: section[1].to_string(),
                    start_addr: 0,
                });
            }

            _ => panic!("Unknown section: {}", section[0]),
        }
    }

    fn get_var_address(&self, name: &str) -> Option<u32> {
        self.sections
            .iter()
            .find(|s| s.name() == name)
            .map(|s| s.start_addr())
    }

    fn read_from_section(&self, name: &str, offset: usize, size: usize) -> &[u8] {
        let section = self
            .sections
            .iter()
            .find(|s| s.name() == name)
            .unwrap_or_else(|| panic!("Section {} not found", name));

        let addr = section.start_addr() as usize + offset;
        &self.memory[addr..addr + size]
    }

    // Добавляем таблицу системных вызовов
    fn syscall_table(&mut self, num: u32) {
        // https://gist.github.com/GabriOliv/a9411fa771a1e5d94105cb05cbaebd21
        match num {
            // Exit
            1 => self.running = false,
            // Read mode
            3 => {
                match self.regs.ebx {
                    0 => {
                        let buffer_addr = self.regs.ecx as usize;
                        let buffer_size = self.regs.edx as usize;

                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).unwrap();
                        let input_bytes = input.as_bytes();

                        // Записываем только то, что помещается в буфер
                        let bytes_to_copy = std::cmp::min(input_bytes.len(), buffer_size);
                        self.write_memory(buffer_addr, &input_bytes[..bytes_to_copy]);

                        // Возвращаем количество прочитанных байт в EAX
                        self.regs.eax = bytes_to_copy as u32;
                        dbg!(&self.regs.ecx);
                    }
                    _ => panic!("Unknown ebx: {:08X}", self.regs.ebx),
                };
            }
            // Write mode
            4 => {
                println!("Syscall 0: EAX = {}", self.regs.eax);
            }
            _ => panic!("Unknown syscall: {}", num),
        }
    }

    // Модифицируем команду syscall
    fn syscall(&mut self) {
        println!("Вызов syscall");
        // В x86 номер syscall обычно передается через EAX
        let syscall_num = self.regs.eax;
        self.syscall_table(syscall_num);
    }

    // Запись данных в память
    fn write_memory(&mut self, addr: usize, data: &[u8]) {
        let size = data.len();
        //assert!(size & 0x3 == 0, "memory size must be multiple of 4");
        // а хер знает, надо эт
        //или нет

        let next_power = size.next_power_of_two();
        let offset = next_power - size;
        let aligned_size = size + offset;

        // Выравнивание адреса
        let align = next_power;
        let aligned_addr = (addr + (align - 1)) & !(align - 1);

        if aligned_addr + aligned_size > self.memory.len() {
            panic!("Memory access out of bounds");
        }

        self.memory[aligned_addr..aligned_addr + size].copy_from_slice(data);
    }

    // Чтение данных из памяти
    fn read_memory(&self, addr: usize, size: usize) -> &[u8] {
        if addr + size > self.memory.len() {
            panic!("Memory read out of range");
        }
        &self.memory[addr..addr + size]
    }

    // Исполнение одной инструкции
    fn execute(&mut self, instruction: &str) {
        let parts: Vec<&str> = instruction.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        match parts[0].to_lowercase().as_str() {
            "section" => self.section(&parts[1..]),
            // Я ебал как вызывать alloc по другому поэтому хотфикс-костыль
            "start:" => self.allocate_memory_for_sections(),

            "mov" => self.mov(&parts[1..]),
            "add" => self.add(&parts[1..]),
            "sub" => self.sub(&parts[1..]),
            "jmp" => self.jmp(&parts[1..]),
            "syscall" => self.syscall(),
            "xor" => self.xor(&parts[1..]),
            "nop" => {} // Ничего не делаем
            "hlt" => self.running = false,
            _ => panic!("Unknown instruction: {}", parts[0]),
        }

        // Увеличиваем указатель инструкций, если не было прыжка
        if parts[0].to_lowercase() != "jmp" {
            self.regs.eip += 1;
        }
    }

    // Команда MOV
    fn mov(&mut self, operands: &[&str]) {
        if operands.len() != 2 {
            panic!("MOV requires 2 operands");
        }

        let dest = operands[0];
        let src = operands[1];

        if src.starts_with('[') && src.ends_with(']') {
            let reg_name = &src[1..src.len() - 1];
            let addr = self.regs.get(reg_name) as usize;
            let value = u32::from_le_bytes(self.read_memory(addr, 4).try_into().unwrap());
            self.regs.set(dest, value);
            return;
        }

        if let Some(addr) = self.get_var_address(src) {
            dbg!(&src);
            dbg!(addr);
            self.regs.set(dest, addr);
            return;
        }

        // Проверяем, является ли src числом
        if let Ok(value) = src.parse::<u32>() {
            self.regs.set(dest, value);
        } else {
            // Иначе предполагаем, что это регистр
            let src_value = self.regs.get(src);
            self.regs.set(dest, src_value);
        }
    }

    // Команда ADD
    fn add(&mut self, operands: &[&str]) {
        if operands.len() != 2 {
            panic!("ADD requires 2 operands");
        }

        let dest = operands[0];
        let src = operands[1];

        let dest_value = self.regs.get(dest);
        let src_value = if let Ok(value) = src.parse::<u32>() {
            value
        } else {
            self.regs.get(src)
        };

        let result = dest_value.wrapping_add(src_value);
        self.regs.set(dest, result);

        // Обновляем флаги
        self.update_flags(result);
    }

    // Команда SUB
    fn sub(&mut self, operands: &[&str]) {
        if operands.len() != 2 {
            panic!("SUB requires 2 operands");
        }

        let dest = operands[0];
        let src = operands[1];

        let dest_value = self.regs.get(dest);
        let src_value = if let Ok(value) = src.parse::<u32>() {
            value
        } else {
            self.regs.get(src)
        };

        let result = dest_value.wrapping_sub(src_value);
        self.regs.set(dest, result);

        // Обновляем флаги
        self.update_flags(result);
    }

    // Команда JMP
    fn jmp(&mut self, operands: &[&str]) {
        if operands.len() != 1 {
            panic!("JMP requires 1 operand");
        }

        let target = if let Ok(addr) = operands[0].parse::<u32>() {
            addr
        } else {
            self.regs.get(operands[0])
        };

        self.regs.eip = target;
    }

    fn xor(&mut self, operands: &[&str]) {
        if operands.len() != 2 {
            panic!("XOR requires 2 operands");
        }

        let dest = operands[0];
        let src = operands[1];

        let dest_value = self.regs.get(dest);
        let src_value = if let Ok(value) = src.parse::<u32>() {
            value
        } else {
            self.regs.get(src)
        };

        let result = src_value ^ dest_value;
        self.regs.set(dest, result);

        self.update_flags(result);
    }

    // Обновление флагов
    fn update_flags(&mut self, result: u32) {
        // Просто заметка о том, где и какие флаги лежат в памяти
        // Криво ну и хрен с ним!
        //
        //  15 14 13 12  11   10    9    8    7    6   5   4  3   2  1   0
        //  _______________________________________________________________
        // |__|__|__|__| of | df | if | tf | sf | zf |_| af |_| pf |_| cf |
        //

        // Zero flag (zf)
        if result == 0 {
            self.regs.eflags |= 1 << 6; // ZF is bit 6
        } else {
            self.regs.eflags &= !(1 << 6);
        }

        // Sign flag (для 32-битных чисел - бит 31) (sf)
        if (result as i32) < 0 {
            self.regs.eflags |= 1 << 7; // SF is bit 7
        } else {
            self.regs.eflags &= !(1 << 7);
        }

        // Parity flag (pf)
        let parity = result.count_ones() % 2 == 0;
        if parity {
            self.regs.eflags |= 1 << 2; // PF is bit 2
        } else {
            self.regs.eflags &= !(1 << 2);
        }
    }

    // Запуск эмулятора
    fn run(&mut self, program: &[&str]) {
        self.running = true;
        self.regs.eip = 0;

        while self.running && (self.regs.eip as usize) < program.len() {
            let instruction = program[self.regs.eip as usize];
            self.execute(instruction);
        }
    }
}

fn main() {
    // Создаем эмулятор с 1Kb памяти
    let mut cpu = CPU::new(1024);

    cpu.write_memory(0, &[5u8; 52]);
    let mem = cpu.read_memory(0, 128).to_vec();

    // Простая программа на ассемблере
    let program = [
        "mov eax 10",
        "mov ebx 20",
        "add eax ebx",
        "sub eax 5",
        "mov ecx eax",
        "mov eax 4",
        "syscall",
        "mov ebx 1",
        "mov eax 1",   // exit
        "xor ebx ebx", // exit code
        "syscall",
    ];

    // Запускаем программу
    cpu.run(&program);

    // Выводим состояние регистров после выполнения
    println!("Registers after execution:");
    println!("EAX: {:08X}", cpu.regs.eax);
    println!("EBX: {:08X}", cpu.regs.ebx);
    println!("ECX: {:08X}", cpu.regs.ecx);
    println!("EDX: {:08X}", cpu.regs.edx);
    println!("ESP: {:08X}", cpu.regs.esp);
    println!("EBP: {:08X}", cpu.regs.ebp);
    println!("EIP: {:08X}", cpu.regs.eip);
    println!("EFLAGS: {:08X}", cpu.regs.eflags);
    println!("memory: {:?}", cpu.memory);
    println!("read mem: {:?}", &mem);
    println!("Exit code: {:08X}", cpu.regs.ebx);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn set_get_regs() {
        let mut cpu = CPU::new(1024);

        let program = [
            "mov eax 10",
            "mov ebx 20",
            "add eax ebx",
            "sub eax 5",
            "mov ecx eax",
            "mov edx 0",
            "xor edx 1",
        ];

        cpu.run(&program);

        assert_eq!(cpu.regs.eax, 25);
        assert_eq!(cpu.regs.ebx, 20);
        assert_eq!(cpu.regs.ecx, 25);
        assert_eq!(cpu.regs.edx, 1);
    }

    #[test]
    fn write_read_memory() {
        let mut cpu = CPU::new(1024);

        cpu.write_memory(0, &[1; 16]);

        let program = ["mov eax 1", "xor eax 0", "syscall"];

        cpu.run(&program);

        assert_eq!(cpu.read_memory(0, 16), vec![1; 16]);
    }

    #[ignore = "Трубется ввод данных с клавиатуры"]
    #[test]
    fn read_stdin() {
        let mut cpu = CPU::new(1024);

        let program = [
            "section .bss input_buffer resb 16",
            "section .bss input_buf resb 16",
            "start:",
            "mov eax 3",
            "mov ebx 0",
            "mov ecx input_buffer",
            "mov edx 16",
            "syscall",
            "mov eax 3",
            "mov ebx 0",
            "mov ecx input_buf",
            "mov edx 16",
            "syscall",
            "hlt",
        ];

        cpu.run(&program);

        // TODO: Придумать mock для stdin

        dbg!(&cpu.sections);
        dbg!(cpu.read_memory(0, 32));

        assert_eq!(cpu.read_memory(0, 13), "hello world!\n".as_bytes());
        // Смещение на 3 потому что под hellow world выделилось 16 байт, а сама строка занимает 13
        // байт, а значит остается еще 3 байта свободных в виде нулей.
        assert_eq!(cpu.read_memory(13 + 3, 4), "hi!\n".as_bytes());
    }
}
