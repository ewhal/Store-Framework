CREATE TABLE IF NOT EXISTS `users` (
	`id` int(256) NOT NULL AUTO_INCREMENT,
	`user_name` varchar(60) NOT NULL,
	`user_email` varchar(60) NOT NULL,
	`user_password` varchar(60) NOT NULL,
	`user_created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`user_last_login` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
	`admin` BOOLEAN NOT NULL,  
	PRIMARY KEY (`id`),
	UNIQUE KEY `user_name` (`user_name`),
	UNIQUE KEY `user_email` (`user_email`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `products` (
	`id` int(255) NOT NULL AUTO_INCREMENT,
	`product_name` varchar(256) NOT NULL,
	`dscription` varchar(512) NOT NULL,
	`image` varchar(60) NOT NULL,
	`price` float(11) NOT NULL,
	PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
