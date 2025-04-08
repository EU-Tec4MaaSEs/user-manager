package gr.atc.t4m;

import org.springframework.boot.SpringApplication;

public class TestT4mUserManagerApplication {

	public static void main(String[] args) {
		SpringApplication.from(T4mUserManagerApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
