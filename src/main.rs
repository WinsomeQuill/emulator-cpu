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

// Состояние процессора
struct CPU {
    regs: Registers,
    memory: Vec<u8>,
    running: bool,
}

impl CPU {
    fn new(memory_size: usize) -> Self {
        CPU {
            regs: Registers::new(),
            memory: vec![0; memory_size],
            running: false,
        }
    }

    // Добавляем таблицу системных вызовов
    fn syscall_table(&mut self, num: u32) {
        // https://gist.github.com/GabriOliv/a9411fa771a1e5d94105cb05cbaebd21
        match num {
            // Read mode
            3 => {
                // TODO: А буфер то не настоящий! Нужно читать размер из EDX.
                // Желательно еще читать ECX

                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                self.regs.eax = input.trim().parse().unwrap_or(0);
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
        assert!(size & 0x3 == 0, "memory size must be multiple of 4");

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
            "mov" => self.mov(&parts[1..]),
            "add" => self.add(&parts[1..]),
            "sub" => self.sub(&parts[1..]),
            "jmp" => self.jmp(&parts[1..]),
            "syscall" => self.syscall(),
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

    // Обновление флагов
    fn update_flags(&mut self, result: u32) {
        // Zero flag
        if result == 0 {
            self.regs.eflags |= 1 << 6; // ZF is bit 6
        } else {
            self.regs.eflags &= !(1 << 6);
        }

        // Sign flag (для 32-битных чисел - бит 31)
        if (result as i32) < 0 {
            self.regs.eflags |= 1 << 7; // SF is bit 7
        } else {
            self.regs.eflags &= !(1 << 7);
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

    cpu.write_memory(0, &vec![5u8; 52]);
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
}
