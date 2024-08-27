package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

//Repository는 어노테이션을 안써도됨 상속을 받아서 jpa안에 빈이 있다라는말
public interface UserRepository extends JpaRepository<User, Integer> {

}
