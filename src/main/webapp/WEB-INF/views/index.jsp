<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="jakarta.tags.core" %>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	this is my index.jsp
	<br>
	<form action="<c:url value='/logout' />" method="post">
	    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
	    <button>Logout</button>
	</form>
</body>
</html>