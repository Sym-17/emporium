import React from "react";

function LinkedInIcon({ footerOrNot }: { footerOrNot: string }) {
  return (
    <svg
      className={`${footerOrNot === "true" ? "fill-gray-300" : "fill-primary"}`}
      version="1.1"
      id="Icons"
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
    >
      <path
        d="M23,0H9C4,0,0,4,0,9v14c0,5,4,9,9,9h14c5,0,9-4,9-9V9C32,4,28,0,23,0z M12,25c0,0.6-0.4,1-1,1H7c-0.6,0-1-0.4-1-1V13
	c0-0.6,0.4-1,1-1h4c0.6,0,1,0.4,1,1V25z M9,11c-1.7,0-3-1.3-3-3s1.3-3,3-3s3,1.3,3,3S10.7,11,9,11z M26,25c0,0.6-0.4,1-1,1h-3
	c-0.6,0-1-0.4-1-1v-3.5v-1v-2c0-0.8-0.7-1.5-1.5-1.5S18,17.7,18,18.5v2v1V25c0,0.6-0.4,1-1,1h-3c-0.6,0-1-0.4-1-1V13
	c0-0.6,0.4-1,1-1h4c0.3,0,0.5,0.1,0.7,0.3c0.6-0.2,1.2-0.3,1.8-0.3c3,0,5.5,2.5,5.5,5.5V25z"
      />
    </svg>
  );
}

export default LinkedInIcon;
