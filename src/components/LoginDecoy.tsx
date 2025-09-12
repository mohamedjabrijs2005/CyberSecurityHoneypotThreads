import React from 'react';

const LoginDecoy: React.FC = () => {
  return (
	<div>
	  <h2>Login</h2>
	  {/* Decoy login form */}
	  <form>
		<div>
		  <label htmlFor="username">Username:</label>
		  <input type="text" id="username" name="username" />
		</div>
		<div>
		  <label htmlFor="password">Password:</label>
		  <input type="password" id="password" name="password" />
		</div>
		<button type="submit">Login</button>
	  </form>
	</div>
  );
};

export default LoginDecoy;